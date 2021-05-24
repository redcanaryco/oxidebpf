use libc::{pid_t, syscall};
use nix::errno::errno;
use nix::{ioctl_none, ioctl_write_int};
use std::borrow::Borrow;
use std::convert::{From, TryFrom, TryInto};
use std::error::Error;
use std::mem::{uninitialized, MaybeUninit};
use std::os::raw::{c_int, c_short, c_uchar, c_uint, c_ulong};
use std::os::unix::io::RawFd;
use syscalls::{SYS_bpf, SYS_perf_event_open, SYS_setns};

use crate::bpf::constant::bpf_cmd::{
    BPF_MAP_CREATE, BPF_MAP_LOOKUP_ELEM, BPF_MAP_UPDATE_ELEM, BPF_PROG_LOAD,
};
use crate::bpf::{
    constant::perf_ioctls, BpfAttr, BpfInsn, BpfProgLoad, KeyVal, MapConfig, MapElem, PerfEventAttr,
};
use crate::error::*;
use std::ffi::{CStr, CString};

type BpfMapType = u32;

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
unsafe fn sys_bpf(
    cmd: u32,
    bpf_attr: Box<BpfAttr>,
    size: usize,
) -> Result<usize, EbpfSyscallError> {
    let ret = syscall(
        (SYS_bpf as i32).into(),
        cmd,
        bpf_attr.as_ref() as *const _,
        size,
    );
    if ret < 0 {
        return Err(EbpfSyscallError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as usize)
}

// perf_event_open
// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
// Glibc does not provide a wrapper for this system call; call it
// using syscall(2).  See the example below.
//
// The official way of knowing if perf_event_open() support is
// enabled is checking for the existence of the file
// /proc/sys/kernel/perf_event_paranoid.
pub(crate) fn perf_event_open(
    attr: PerfEventAttr,
    pid: pid_t,
    cpu: i32,
    group_fd: RawFd,
    flags: c_ulong,
) -> Result<RawFd, EbpfSyscallError> {
    if !std::path::Path::new("/proc/sys/kernel/perf_event_paranoid").exists() {
        return Err(EbpfSyscallError::PerfEventDoesNotExist);
    }
    let ret = unsafe {
        syscall(
            (SYS_perf_event_open as i32).into(),
            attr,
            pid,
            cpu,
            group_fd,
            flags,
        )
    };
    if ret < 0 {
        return Err(EbpfSyscallError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as RawFd)
}

// setns
pub(crate) fn setns(fd: RawFd, nstype: i32) -> Result<usize, EbpfSyscallError> {
    let ret = unsafe { syscall((SYS_setns as i32).into(), fd, nstype) };
    if ret < 0 {
        return Err(EbpfSyscallError::LinuxError(nix::errno::from_i32(errno())));
    }
    Ok(ret as usize)
}

// ioctl( PERF_EVENT_IOC_SET_BPF )
ioctl_write_int!(
    u_perf_event_ioc_set_bpf,
    perf_ioctls::PERF_EVENT_IOC_MAGIC,
    perf_ioctls::PERF_EVENT_IOC_SET_BPF
);
pub(crate) fn perf_event_ioc_set_bpf(perf_fd: RawFd, data: i32) -> Result<i32, EbpfSyscallError> {
    let data_unwrapped = match data.try_into() {
        Ok(d) => d,
        Err(e) => 0, // Should be infallible
    };
    match unsafe { u_perf_event_ioc_set_bpf(perf_fd, data_unwrapped) } {
        Ok(i) => Ok(i),
        Err(e) => Err(EbpfSyscallError::PerfIoctlError(e)),
    }
}

// ioctl( PERF_EVENT_IOC_ENABLE )
ioctl_none!(
    u_perf_event_ioc_enable,
    perf_ioctls::PERF_EVENT_IOC_MAGIC,
    perf_ioctls::PERF_EVENT_IOC_ENABLE
);
pub(crate) fn perf_event_ioc_enable(perf_fd: RawFd) -> Result<i32, EbpfSyscallError> {
    match unsafe { u_perf_event_ioc_enable(perf_fd) } {
        Ok(i) => Ok(i),
        Err(e) => Err(EbpfSyscallError::PerfIoctlError(e)),
    }
}

// ioctl( PERF_EVENT_IOC_DISABLE )
ioctl_none!(
    u_perf_event_ioc_disable,
    perf_ioctls::PERF_EVENT_IOC_MAGIC,
    perf_ioctls::PERF_EVENT_IOC_DISABLE
);
pub(crate) fn perf_event_ioc_disable(perf_fd: RawFd) -> Result<i32, EbpfSyscallError> {
    match unsafe { u_perf_event_ioc_disable(perf_fd) } {
        Ok(i) => Ok(i),
        Err(e) => Err(EbpfSyscallError::PerfIoctlError(e)),
    }
}

// syscall( BPF_PROG_LOAD )
pub(crate) fn bpf_prog_load(
    prog_type: u32,
    insns: Vec<BpfInsn>,
    license: String,
) -> Result<(), EbpfSyscallError> {
    let insn_cnt = insns.len();
    let insns = Box::new(insns);
    let license = match CString::new(license.as_bytes()) {
        Ok(s) => s,
        Err(e) => return Err(EbpfSyscallError::CStringConversionError(e)),
    };
    let mut bpf_prog_load = BpfProgLoad {
        prog_type,
        insn_cnt: insn_cnt as u32,
        insns: insns.as_ref() as *const _ as u64,
        license: &license as *const _ as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
    };

    let mut bpf_attr = Box::new(BpfAttr {
        BpfProgLoad: bpf_prog_load,
    });
    let bpf_attr_size = std::mem::size_of::<BpfProgLoad>();
    unsafe {
        sys_bpf(BPF_PROG_LOAD, bpf_attr, bpf_attr_size)?;
        Ok(())
    }
}

/// Caller is responsible for ensuring T is the correct type for this map
pub(crate) fn bpf_map_lookup_elem<K, V>(map_fd: RawFd, key: K) -> Result<V, EbpfSyscallError> {
    let mut buf = MaybeUninit::zeroed();
    let mut map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &mut buf as *mut _ as u64,
        },
        flags: 0,
    };
    let mut bpf_attr = Box::new(BpfAttr { MapElem: map_elem });
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(BPF_MAP_LOOKUP_ELEM, bpf_attr, bpf_attr_size)?;
        Ok(buf.assume_init())
    }
}

pub(crate) fn bpf_map_update_elem<K, V>(
    map_fd: RawFd,
    key: K,
    val: V,
) -> Result<(), EbpfSyscallError> {
    let mut map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &val as *const V as u64,
        },
        flags: 0,
    };
    let mut bpf_attr = Box::new(BpfAttr { MapElem: map_elem });
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(BPF_MAP_UPDATE_ELEM, bpf_attr, bpf_attr_size)?;
    }
    Ok(())
}

pub(crate) fn bpf_map_create(
    map_type: BpfMapType,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: u32,
) -> Result<RawFd, EbpfSyscallError> {
    let mut map_config = MapConfig {
        map_type: map_type as u32,
        key_size: key_size,
        value_size: value_size,
        max_entries: max_entries,
    };
    let mut bpf_attr = Box::new(BpfAttr {
        MapConfig: map_config,
    });
    let bpf_attr_size = std::mem::size_of::<BpfAttr>();

    unsafe {
        let fd = sys_bpf(BPF_MAP_CREATE, bpf_attr, bpf_attr_size)?;
        Ok(fd as RawFd)
    }
}

#[cfg(test)]
mod tests {
    use std::os::raw::c_uint;
    use std::os::unix::io::RawFd;

    use crate::bpf::constant::bpf_map_type::BPF_MAP_TYPE_ARRAY;
    use crate::bpf::syscall::{bpf_map_lookup_elem, perf_event_ioc_set_bpf, perf_event_open};
    use crate::bpf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};
    use crate::error::EbpfSyscallError;
    use nix::errno::Errno;

    fn bpf_panic_error(err: EbpfSyscallError) {
        match err {
            EbpfSyscallError::LinuxError(e) => {
                panic!(
                    "System error [{:?}]: {:?}",
                    (e as Errno),
                    (e as Errno).to_string()
                );
            }
            EbpfSyscallError::PerfEventDoesNotExist => {
                panic!("/proc/sys/kernel/perf_event_paranoid does not exist on this system");
            }
            EbpfSyscallError::PerfIoctlError(e) => {
                panic!("perf IOCTL error: {:?}", e);
            }
            EbpfSyscallError::CStringConversionError(e) => {
                panic!("could not convert string: {:?}", e)
            }
        }
    }

    #[test]
    fn bpf_map_create() {
        match crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ) {
            Err(e) => bpf_panic_error(e),
            _ => {}
        }
    }

    #[test]
    fn bpf_map_create_and_read() {
        let fd: RawFd = match crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                bpf_panic_error(e);
                panic!()
            }
        };

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
        let fd: RawFd = match crate::bpf::syscall::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                bpf_panic_error(e);
                panic!()
            }
        };

        match crate::bpf::syscall::bpf_map_update_elem::<u32, u32>(fd, 5, 50) {
            Ok(_) => {}
            Err(e) => {
                bpf_panic_error(e);
                panic!()
            }
        };

        match crate::bpf::syscall::bpf_map_lookup_elem::<u32, u32>(fd, 5) {
            Ok(val) => {
                assert_eq!(val, 50);
            }
            Err(e) => {
                bpf_panic_error(e);
                panic!()
            }
        }
    }

    #[test]
    fn test_setns() {
        todo!()
    }

    #[test]
    fn test_perf_event_open() {
        todo!();
        match perf_event_open(
            PerfEventAttr {
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
        todo!()
    }
}
