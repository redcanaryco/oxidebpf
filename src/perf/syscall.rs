use std::convert::TryInto;
use std::os::raw::c_ulong;
use std::os::unix::io::RawFd;

use libc::pid_t;
use libc::{syscall, SYS_perf_event_open};
use nix::errno::errno;

use crate::error::OxidebpfError;
use crate::perf::PerfEventAttr;
use nix::{ioctl_none, ioctl_write_int};

// unsafe `ioctl( PERF_EVENT_IOC_SET_BPF )` function
ioctl_write_int!(
    u_perf_event_ioc_set_bpf,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_SET_BPF
);

// unsafe `ioctl( PERF_EVENT_IOC_ENABLE )` function
ioctl_none!(
    u_perf_event_ioc_enable,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_ENABLE
);

// unsafe `ioctl( PERF_EVENT_IOC_DISABLE )` function
ioctl_none!(
    u_perf_event_ioc_disable,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_MAGIC,
    crate::perf::constant::perf_ioctls::PERF_EVENT_IOC_DISABLE
);

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

/// Safe wrapper around `u_perf_event_ioc_enable()`
pub(crate) fn perf_event_ioc_enable(perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    unsafe { u_perf_event_ioc_enable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
}

/// Safe wrapper around `u_perf_event_ioc_disable()`
pub(crate) fn perf_event_ioc_disable(perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    unsafe { u_perf_event_ioc_disable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
}

#[cfg(test)]
mod tests {
    use crate::bpf::syscall::tests::bpf_panic_error;
    use crate::perf::syscall::{perf_event_ioc_set_bpf, perf_event_open};
    use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};
    use std::os::unix::io::RawFd;

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
}
