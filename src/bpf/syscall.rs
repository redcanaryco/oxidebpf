use std::convert::TryInto;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_uint, c_ulong};
use std::os::unix::io::RawFd;
use std::sync::atomic::AtomicPtr;

use libc::{pid_t, syscall, SYS_bpf, SYS_setns, CLONE_NEWNS};
use nix::errno::errno;

use crate::bpf::constant::bpf_cmd::{
    BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
};
use crate::bpf::constant::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY;
use crate::bpf::{
    BpfAttr, BpfCode, BpfInsn, BpfProgAttach, BpfProgLoad, KeyVal, MapConfig, MapElem, SizedBpfAttr,
};
use crate::error::*;
use crate::perf::constant::perf_ioctls;
use crate::perf::PerfEventAttr;

type BpfMapType = u32;

/// Performs `bpf()` syscalls and returns a formatted `OxidebpfError`. The passed [`SizedBpfAttr`] _must_
/// indicate the amount of _bytes_ to be used by this call.
///
/// # Example
/// ```no_run
/// let arg_bpf_attr = SizedBpfAttr {
///     bpf_atr: SomeStruct {
///         SomeVal: 123 as u32,
///         ..Default::default()
///     },
///     size: 4, // we instantiated 1 u32 of size 4 bytes
/// };
/// sys_bpf(BPF_MAP_CREATE, arg_bpf_atr);
/// ```
unsafe fn sys_bpf(cmd: u32, arg_bpf_attr: SizedBpfAttr) -> Result<usize, OxidebpfError> {
    #![allow(clippy::useless_conversion)] // fails to compile otherwise

    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let bpf_attr: BpfAttr = bpf_attr.assume_init();
    let mut bpf_attr = Box::new(bpf_attr);
    let size = arg_bpf_attr.size;
    let arg_bpf_attr = Box::new(arg_bpf_attr.bpf_attr);

    // VERY UNSAFE!!!
    let mut p = arg_bpf_attr.as_ref() as *const BpfAttr as *const u8;
    let mut q = bpf_attr.as_mut() as *mut BpfAttr as *mut u8;
    for _ in 0..=size {
        *q = *p;
        q = q.add(1);
        p = p.add(1);
    }

    let ret = syscall(
        (SYS_bpf as i32).into(),
        cmd,
        bpf_attr.as_ref() as *const _,
        size,
    );
    if ret < 0 {
        return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as usize)
}

/// Loads a BPF program of the given type from a given `Vec<BpfInsn>`.
/// License should (almost) always be GPL.
pub(crate) fn bpf_prog_load(
    prog_type: u32,
    insns: &BpfCode,
    license: String,
) -> Result<RawFd, OxidebpfError> {
    let insn_cnt = insns.0.len();
    let insns = insns.0.clone().into_boxed_slice();
    let license =
        CString::new(license.as_bytes()).map_err(|e| OxidebpfError::CStringConversionError(e))?;
    let bpf_prog_load = BpfProgLoad {
        prog_type,
        insn_cnt: insn_cnt as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        ..Default::default()
    };
    let bpf_attr = SizedBpfAttr {
        bpf_attr: BpfAttr { bpf_prog_load },
        size: 24,
    };
    unsafe {
        let fd = sys_bpf(BPF_PROG_LOAD, bpf_attr)?;
        Ok(fd as RawFd)
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
    use std::convert::TryInto;
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_uint};
    use std::os::unix::io::{FromRawFd, RawFd};

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

    pub(crate) fn bpf_panic_error(err: OxidebpfError) {
        match err {
            OxidebpfError::LinuxError(e) => {
                panic!(
                    "System error [{:?}]: {:?}",
                    (e as Errno),
                    (e as Errno).to_string()
                );
            }
            OxidebpfError::PerfEventDoesNotExist => {
                panic!("/proc/sys/kernel/perf_event_paranoid does not exist on this system");
            }
            OxidebpfError::PerfIoctlError(e) => {
                panic!("perf IOCTL error: {:?}", e);
            }
            OxidebpfError::CStringConversionError(e) => {
                panic!("could not convert string: {:?}", e)
            }
            e => {
                panic!(e)
            }
        }
    }

    #[test]
    fn bpf_map_create() {
        let fd: RawFd = crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            10,
        )
        .map_err(|e| bpf_panic_error(e))
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
        .map_err(|e| bpf_panic_error(e))
        .unwrap();
        defer!(unsafe {
            libc::close(fd);
        });

        match crate::bpf::syscall::bpf_map_lookup_elem::<u32, u32>(fd, 0) {
            Ok(val) => {
                assert_eq!(val, 0);
            }
            Err(e) => {
                bpf_panic_error(e);
                panic!()
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
        .map_err(|e| bpf_panic_error(e))
        .unwrap();
        defer!(unsafe {
            libc::close(fd);
        });

        crate::bpf::syscall::bpf_map_update_elem::<u32, u64>(fd, 5, 50)
            .map_err(|e| bpf_panic_error(e))
            .unwrap();

        match crate::bpf::syscall::bpf_map_lookup_elem::<u32, u64>(fd, 5) {
            Ok(val) => {
                assert_eq!(val, 50);
            }
            Err(e) => {
                bpf_panic_error(e);
                panic!()
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
                let errmsg = nix::errno::Errno::from_i32(errno);
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
            crate::perf::syscall::setns(fd, CLONE_NEWNS)
                .map_err(|e| bpf_panic_error(e))
                .unwrap();
        }
    }

    #[test]
    fn test_bpf_prog_load() {
        // currently fails w/ EACCES because we are not applying relocations
        use std::path::PathBuf;
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test.o"); // TODO: make this a MIT licensed bpf stub program that doesn't need relocations
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(d).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let program_object = program_blueprint.programs.get("sys_ptrace_write").unwrap();
        match bpf_prog_load(
            BPF_PROG_TYPE_KPROBE,
            &program_object.code,
            program_object.license.clone(),
        ) {
            Ok(_fd) => {}
            Err(e) => bpf_panic_error(e),
        };
    }
}
