use libc::{pid_t, syscall, SYS_bpf, SYS_perf_event_open, SYS_setns, CLONE_NEWNS};
use nix::errno::errno;
use nix::{ioctl_none, ioctl_write_int};
use std::convert::TryInto;
use std::mem::MaybeUninit;
use std::os::raw::{c_uint, c_ulong};
use std::os::unix::io::RawFd;

use crate::bpf::constant::bpf_cmd::{
    BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
};
use crate::bpf::{
    BpfAttr, BpfCode, BpfInsn, BpfProgAttach, BpfProgLoad, KeyVal, MapConfig, MapElem,
    PerfEventAttr,
};
use crate::error::*;
use crate::perf::constant::perf_ioctls;
use std::ffi::CString;

type BpfMapType = u32;

/// Performs `bpf()` syscalls and returns a formatted `OxidebpfError`. The passed `BpfAttr`
/// union _must_ be zero initialized before being filled and passed to this call.
unsafe fn sys_bpf(cmd: u32, bpf_attr: Box<BpfAttr>, size: usize) -> Result<usize, OxidebpfError> {
    // https://man7.org/linux/man-pages/man2/syscall.2.html
    // Architecture-specific requirements
    // Each architecture ABI has its own requirements on how system call
    // arguments are passed to the kernel.  For system calls that have a
    // glibc wrapper (e.g., most system calls), glibc handles the
    // details of copying arguments to the right registers in a manner
    // suitable for the architecture.  However, when using syscall() to
    // make a system call, the caller might need to handle architecture-
    // dependent details; this requirement is most commonly encountered
    // on certain 32-bit architectures.
    #![allow(clippy::useless_conversion)] // fails to compile otherwise
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

/// Checks if `perf_event_open()` is supported and if so, calls the syscall.
pub(crate) fn perf_event_open(
    attr: &PerfEventAttr,
    pid: pid_t,
    cpu: i32,
    group_fd: RawFd,
    flags: c_ulong,
) -> Result<RawFd, OxidebpfError> {
    #![allow(clippy::useless_conversion)] // fails to compile otherwise
    if !std::path::Path::new("/proc/sys/kernel/perf_event_paranoid").exists() {
        return Err(OxidebpfError::PerfEventDoesNotExist);
    }
    let ret = unsafe {
        syscall(
            (SYS_perf_event_open as i32).into(),
            attr.clone() as *const _ as u64,
            pid,
            cpu,
            group_fd,
            flags,
        )
    };
    if ret < 0 {
        return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as RawFd)
}

/// Calls the `setns` syscall on the given `fd` with the given `nstype`.
pub(crate) fn setns(fd: RawFd, nstype: i32) -> Result<usize, OxidebpfError> {
    #![allow(clippy::useless_conversion)] // fails to compile otherwise
    let ret = unsafe { syscall((SYS_setns as i32).into(), fd, nstype) };
    if ret < 0 {
        return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as usize)
}

// unsafe `ioctl( PERF_EVENT_IOC_SET_BPF )` function
ioctl_write_int!(
    u_perf_event_ioc_set_bpf,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_SET_BPF
);

/// Safe wrapper around `u_perf_event_ioc_set_bpf()`
pub(crate) fn perf_event_ioc_set_bpf(perf_fd: RawFd, data: i32) -> Result<i32, OxidebpfError> {
    #![allow(clippy::useless_conversion)] // fails to compile otherwise
    let data_unwrapped = match data.try_into() {
        Ok(d) => d,
        Err(_e) => 0, // Should be infallible
    };
    unsafe {
        u_perf_event_ioc_set_bpf(perf_fd, data_unwrapped)
            .map_err(|e| OxidebpfError::PerfIoctlError(e))
    }
}

// unsafe `ioctl( PERF_EVENT_IOC_ENABLE )` function
ioctl_none!(
    u_perf_event_ioc_enable,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_ENABLE
);

/// Safe wrapper around `u_perf_event_ioc_enable()`
pub(crate) fn perf_event_ioc_enable(perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    unsafe { u_perf_event_ioc_enable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
}

// unsafe `ioctl( PERF_EVENT_IOC_DISABLE )` function
ioctl_none!(
    u_perf_event_ioc_disable,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_DISABLE
);

/// Safe wrapper around `u_perf_event_ioc_disable()`
pub(crate) fn perf_event_ioc_disable(perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    unsafe { u_perf_event_ioc_disable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
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
    let bpf_prog_load = MaybeUninit::<BpfProgLoad>::zeroed();
    let mut bpf_prog_load = unsafe { bpf_prog_load.assume_init() };
    bpf_prog_load.prog_type = prog_type;
    bpf_prog_load.insn_cnt = insn_cnt as u32;
    bpf_prog_load.insns = insns.as_ptr() as u64;
    bpf_prog_load.license = license.as_ptr() as u64;
    let slice =
        unsafe { std::slice::from_raw_parts::<BpfInsn>(bpf_prog_load.insns as *const _, insn_cnt) };
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = unsafe { bpf_attr.assume_init() };
    bpf_attr.bpf_prog_load = bpf_prog_load;
    let bpf_attr = Box::new(bpf_attr);
    let bpf_attr_size = std::mem::size_of::<BpfProgLoad>();
    unsafe {
        // TODO: we want the size we actually use, hardcoded as 24 here
        let fd = sys_bpf(BPF_PROG_LOAD, bpf_attr, 24)?; //bpf_attr_size)?;
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
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = unsafe { bpf_attr.assume_init() };
    bpf_attr.map_elem = map_elem;
    let bpf_attr = Box::new(bpf_attr);
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(BPF_MAP_LOOKUP_ELEM, bpf_attr, bpf_attr_size)?;
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
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = unsafe { bpf_attr.assume_init() };
    bpf_attr.map_elem = map_elem;
    let bpf_attr = Box::new(bpf_attr);
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(BPF_MAP_UPDATE_ELEM, bpf_attr, bpf_attr_size)?;
    }
    Ok(())
}

pub(crate) fn bpf_map_create_with_config(map_config: MapConfig) -> Result<RawFd, OxidebpfError> {
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = unsafe { bpf_attr.assume_init() };
    bpf_attr.map_config = map_config;
    let bpf_attr = Box::new(bpf_attr);
    let bpf_attr_size = std::mem::size_of::<BpfAttr>();
    unsafe {
        let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr, bpf_attr_size)?;
        Ok(fd as RawFd)
    }
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
    let map_config = MaybeUninit::<MapConfig>::zeroed();
    let mut map_config = unsafe { map_config.assume_init() };
    map_config.map_type = map_type as u32;
    map_config.key_size = key_size;
    map_config.value_size = value_size;
    map_config.max_entries = max_entries;
    let bpf_attr = MaybeUninit::<BpfAttr>::zeroed();
    let mut bpf_attr = unsafe { bpf_attr.assume_init() };
    bpf_attr.map_config = map_config;
    let bpf_attr = Box::new(bpf_attr);
    let bpf_attr_size = std::mem::size_of::<BpfAttr>();

    unsafe {
        let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr, bpf_attr_size)?;
        Ok(fd as RawFd)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use std::os::raw::{c_int, c_uint};
    use std::os::unix::io::{FromRawFd, RawFd};

    use crate::bpf::constant::bpf_map_type::BPF_MAP_TYPE_ARRAY;
    use crate::bpf::constant::bpf_prog_type::BPF_PROG_TYPE_KPROBE;
    use crate::bpf::syscall::{
        bpf_map_lookup_elem, bpf_prog_load, perf_event_ioc_set_bpf, perf_event_open,
    };
    use crate::bpf::{
        BpfCode, BpfInsn, PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup,
    };
    use crate::error::OxidebpfError;
    use nix::errno::{errno, Errno};
    use scopeguard::defer;
    use std::convert::TryInto;
    use std::ffi::c_void;

    fn bpf_panic_error(err: OxidebpfError) {
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
            _ => {}
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
            crate::bpf::syscall::setns(fd, CLONE_NEWNS)
                .map_err(|e| bpf_panic_error(e))
                .unwrap();
        }
    }

    #[test]
    fn test_perf_event_open() {
        #![allow(unreachable_code)]
        todo!();
        match perf_event_open(
            &PerfEventAttr {
                p_type: 0,
                size: 0,
                config: 0,
                sample_union: PerfSample { sample_freq: 0 },
                sample_type: 0,
                read_format: 0,
                flags: 0,
                wakeup_union: PerfWakeup { wakeup_events: 0 },
                bp_type: 0,
                bp_addr_union: PerfBpAddr { bp_addr: 0 },
                bp_len_union: PerfBpLen { bp_len: 0 },
                branch_sample_type: 0,
                sample_regs_user: 0,
                sample_stack_user: 0,
                clockid: 0,
                sample_regs_intr: 0,
                aux_watermark: 0,
                __reserved_2: 0,
            },
            0,
            0,
            0,
            0,
        ) {
            Ok(_) => {}
            Err(e) => bpf_panic_error(e),
        }
    }

    #[test]
    fn test_perf_event_ioc_set_bpf() {
        #![allow(unreachable_code)]
        todo!();
        let perf_fd: RawFd = 0;
        match perf_event_ioc_set_bpf(perf_fd, 0) {
            Ok(_) => {}
            Err(_) => {}
        }
    }

    #[test]
    fn test_perf_event_ioc_disable() {
        todo!()
    }

    #[test]
    fn test_bpf_prog_load() {
        #![allow(unreachable_code)]
        // fails currently, EINVAL
        todo!();
        match bpf_prog_load(
            BPF_PROG_TYPE_KPROBE,
            &BpfCode { 0: vec![] },
            "GPL".to_string(),
        ) {
            Ok(_fd) => {}
            Err(e) => bpf_panic_error(e),
        };
    }
}
