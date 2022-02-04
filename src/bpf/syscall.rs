#[cfg(feature = "log_buf")]
use lazy_static::lazy_static;
use retry::delay::NoDelay;
use retry::{retry_with_index, OperationResult};
use slog::info;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use Errno::EAGAIN;

use libc::{c_uint, syscall, SYS_bpf};
use nix::errno::{errno, Errno};

use crate::bpf::constant::bpf_cmd::{
    BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
};
use crate::bpf::{BpfAttr, BpfCode, BpfProgLoad, KeyVal, MapConfig, MapElem, SizedBpfAttr};
use crate::error::*;
use crate::LOGGER;

pub type BpfMapType = u32;

#[cfg(feature = "log_buf")]
lazy_static! {
    static ref LOG_BUF_SIZE_BYTE: usize = std::env::var("LOG_SIZE")
        .unwrap_or_else(|_| "4096".to_string())
        .trim()
        .parse::<usize>()
        .unwrap_or(4096);
}

/// Performs `bpf()` syscalls and returns a formatted `OxidebpfError`. The passed [`SizedBpfAttr`] _must_
/// indicate the amount of _bytes_ to be used by this call.
///
/// # Example
/// ```ignore
/// let arg_bpf_attr = SizedBpfAttr {
///     bpf_attr: SomeStruct {
///         SomeVal: 123 as u32,
///         ..Default::default()
///     },
///     size: 4, // we instantiated 1 u32 of size 4 bytes
/// };
/// sys_bpf(BPF_MAP_CREATE, arg_bpf_attr);
/// ```
unsafe fn sys_bpf(cmd: u32, arg_bpf_attr: SizedBpfAttr) -> Result<usize, OxidebpfError> {
    #![allow(clippy::useless_conversion)] // fails to compile otherwise

    let size = arg_bpf_attr.size;
    let ptr: *const BpfAttr = &arg_bpf_attr.bpf_attr;

    let mut e = 0;

    // ebpf can fail with EAGAIN for a variety of reasons, just retry it.
    let result = retry_with_index(NoDelay.take(5), |idx| {
        let ret = syscall((SYS_bpf as i32).into(), cmd, ptr, size);

        if ret < 0 {
            e = errno();
            info!(
                LOGGER.0,
                "sys_bpf(); cmd: {}; errno: {}; arg_bpf_attr: {:?}", cmd, e, arg_bpf_attr
            );
            if Errno::from_i32(e) == EAGAIN && idx < 5 {
                OperationResult::Retry("EAGAIN")
            } else {
                OperationResult::Err("Unrecoverable error retrying BPF load")
            }
        } else {
            OperationResult::Ok(ret as usize)
        }
    });

    match result {
        Ok(size) => Ok(size),
        Err(err) => {
            if e == 0 {
                Err(err.into())
            } else {
                Err(OxidebpfError::LinuxError(
                    format!("sys_bpf({}, {:#?})", cmd, arg_bpf_attr),
                    Errno::from_i32(e),
                ))
            }
        }
    }
}

/// Loads a BPF program of the given type from a given `Vec<BpfInsn>`.
/// License should (almost) always be GPL.
pub(crate) fn bpf_prog_load(
    prog_type: u32,
    insns: &BpfCode,
    license: String,
    kernel_version: u32,
) -> Result<RawFd, OxidebpfError> {
    #![allow(clippy::redundant_closure)] // it's not a function clippy
    let insn_cnt = insns.0.len();
    let insns = insns.0.clone().into_boxed_slice();
    let license =
        CString::new(license.as_bytes()).map_err(|e| OxidebpfError::CStringConversionError(e))?;

    #[cfg(feature = "log_buf")]
    let log_buf = vec![0u8; *LOG_BUF_SIZE_BYTE];
    let bpf_prog_load = BpfProgLoad {
        prog_type,
        insn_cnt: insn_cnt as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        kern_version: kernel_version,
        #[cfg(feature = "log_buf")]
        log_level: 1,
        #[cfg(feature = "log_buf")]
        log_size: *LOG_BUF_SIZE_BYTE as u32,
        #[cfg(feature = "log_buf")]
        log_buf: log_buf.as_ptr() as u64,
        ..Default::default()
    };
    let bpf_attr = SizedBpfAttr {
        bpf_attr: BpfAttr { bpf_prog_load },
        size: 48, // 48 = minimum for 4.4
    };
    unsafe {
        match sys_bpf(BPF_PROG_LOAD, bpf_attr) {
            Ok(fd) => Ok(fd as RawFd),
            Err(e) => {
                info!(
                    LOGGER.0,
                    "bpf_prog_load(); error with sys_bpf; bpf_attr: {:?}", bpf_attr
                );
                #[cfg(feature = "log_buf")]
                {
                    let log_string = String::from_utf8(log_buf)
                        .unwrap_or_else(|_| String::from(""))
                        .trim_matches('\0')
                        .to_string();
                    let last_chars: String = log_string
                        .chars()
                        .rev()
                        .take(100)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    info!(LOGGER.0, "bpf_prog_load(); log_buf: {}", last_chars);
                    Err(OxidebpfError::BpfProgLoadError((Box::new(e), log_string)))
                }
                #[cfg(not(feature = "log_buf"))]
                {
                    Err(OxidebpfError::BpfProgLoadError((
                        Box::new(e),
                        "".to_string(),
                    )))
                }
            }
        }
    }
}

/// Look up an element of type `V` with key of type `K` from a given map. Specific behavior depends
/// on the type of map.
/// Caller is responsible for ensuring K and V are the correct types for this map.
pub(crate) fn bpf_map_lookup_elem<K, V>(map_fd: RawFd, key: K) -> Result<V, OxidebpfError> {
    let mut buf = MaybeUninit::zeroed();
    let map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &mut buf as *mut _ as u64,
        },
        flags: 0,
    };

    let bpf_attr = SizedBpfAttr {
        bpf_attr: BpfAttr { map_elem },
        size: std::mem::size_of::<MapElem>(),
    };
    unsafe {
        sys_bpf(BPF_MAP_LOOKUP_ELEM, bpf_attr)?;
        Ok(buf.assume_init())
    }
}

/// Update an element of type `V` with key of type `K` in a given map. Specific behavior depends on
/// the type of map.
pub(crate) fn bpf_map_update_elem<K, V>(
    map_fd: RawFd,
    key: K,
    val: V,
) -> Result<(), OxidebpfError> {
    let map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &val as *const V as u64,
        },
        flags: 0,
    };
    let bpf_attr = SizedBpfAttr {
        bpf_attr: BpfAttr { map_elem },
        size: std::mem::size_of::<MapElem>(),
    };
    unsafe {
        sys_bpf(BPF_MAP_UPDATE_ELEM, bpf_attr)?;
    }
    Ok(())
}

pub(crate) unsafe fn bpf_map_create_with_sized_attr(
    bpf_attr: SizedBpfAttr,
) -> Result<RawFd, OxidebpfError> {
    let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr)?;
    Ok(fd as RawFd)
}

/// The caller must provide a `size` that indicates the amount of _bytes_ used in `map_config`.
/// See the example for [`sys_bpf`](Fn@sys_bpf).
pub(crate) unsafe fn bpf_map_create_with_config(
    map_config: MapConfig,
    size: usize,
) -> Result<RawFd, OxidebpfError> {
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = bpf_attr.assume_init();
    bpf_attr.map_config = map_config;
    let bpf_attr = SizedBpfAttr { bpf_attr, size };
    let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr)?;
    Ok(fd as RawFd)
}

/// Create a map of the given type with given key size, value size, and number of entries.
/// The sizes should be the size of key type and value type in bytes, which can be determined
/// with `std::mem::size_of::<T>()` where `T` is the type of the key or value.
pub(crate) fn bpf_map_create(
    map_type: BpfMapType,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: u32,
) -> Result<RawFd, OxidebpfError> {
    let map_config = MapConfig {
        map_type: map_type as u32,
        key_size,
        value_size,
        max_entries,
        ..Default::default()
    };
    let bpf_attr = SizedBpfAttr {
        bpf_attr: BpfAttr { map_config },
        size: 16,
    };

    unsafe {
        let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr)?;
        Ok(fd as RawFd)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
pub(crate) mod tests {
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_uint};
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::path::PathBuf;

    use nix::errno::{errno, Errno};
    use scopeguard::defer;

    use crate::blueprint::ProgramBlueprint;
    use crate::bpf::constant::bpf_map_type::BPF_MAP_TYPE_ARRAY;
    use crate::bpf::constant::bpf_prog_type::BPF_PROG_TYPE_KPROBE;
    use crate::bpf::syscall::{bpf_map_lookup_elem, bpf_prog_load};
    use crate::bpf::{BpfCode, BpfInsn};
    use crate::error::OxidebpfError;
    use crate::perf::syscall::{perf_event_ioc_set_bpf, perf_event_open};
    use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};
    use std::fs;

    #[test]
    fn bpf_map_create() {
        let fd: RawFd = crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            10,
        )
        .unwrap();
        defer!(unsafe {
            libc::close(fd);
        });
    }

    #[test]
    fn bpf_map_create_and_read() {
        let fd: RawFd = crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        )
        .unwrap();
        defer!(unsafe {
            libc::close(fd);
        });

        match crate::bpf::syscall::bpf_map_lookup_elem::<u32, u32>(fd, 0) {
            Ok(val) => {
                assert_eq!(val, 0);
            }
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }

    #[test]
    fn bpf_map_create_and_write_and_read() {
        let fd: RawFd = crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u64>() as c_uint,
            20,
        )
        .unwrap();
        defer!(unsafe {
            libc::close(fd);
        });

        crate::bpf::syscall::bpf_map_update_elem::<u32, u64>(fd, 5, 50).unwrap();

        match crate::bpf::syscall::bpf_map_lookup_elem::<u32, u64>(fd, 5) {
            Ok(val) => {
                assert_eq!(val, 50);
            }
            Err(e) => {
                panic!("{:?}", e)
            }
        }
    }

    #[repr(C)]
    struct Arg {
        arg: u32,
    }

    extern "C" fn clone_child(_: *mut c_void) -> c_int {
        // Here be dragons. Do not deref `_`. Sleep should get scheduler to give
        // execution back to parent process.
        std::thread::sleep(std::time::Duration::from_millis(1));
        0
    }

    #[test]
    fn test_setns() {
        use libc::{clone, CLONE_NEWNS, SIGCHLD};
        use memmap::MmapMut;
        use std::os::unix::io::AsRawFd;

        let mut arg = Arg { arg: 0x1337beef };
        let mut stack = MmapMut::map_anon(1024 * 1024).unwrap();
        unsafe {
            let ret = clone(
                clone_child,
                &mut stack as *mut _ as *mut _,
                CLONE_NEWNS,
                &mut arg as *mut _ as *mut _,
            );
            if ret < 0 {
                let errno = errno();
                let errmsg = Errno::from_i32(errno);
                panic!("could not create new mount namespace: {:?}", errmsg);
            }
            // read mount ns
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(format!("/proc/{}/ns/mnt", ret))
                .expect("Could not open mount ns file");
            let fd = file.as_raw_fd();

            // switch mnt namespace
            crate::perf::syscall::setns(fd, CLONE_NEWNS).unwrap();
        }
    }

    #[test]
    fn test_bpf_prog_load() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        let data = fs::read(program).unwrap();
        let blueprint = ProgramBlueprint::new(&data, None).unwrap();

        let program_object = blueprint.programs.get("test_program").unwrap();
        match bpf_prog_load(
            BPF_PROG_TYPE_KPROBE,
            &program_object.code,
            program_object.license.clone(),
            program_object.kernel_version,
        ) {
            Ok(_fd) => {}
            Err(e) => panic!("{:?}", e),
        };
    }
}
