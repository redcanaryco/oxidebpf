use std::convert::TryInto;
use std::fs::OpenOptions;
use std::os::linux::fs::MetadataExt;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::{IntoRawFd, RawFd};
use std::path::PathBuf;

use lazy_static::lazy_static;
use libc::pid_t;
use libc::{syscall, SYS_perf_event_open, CLONE_NEWNS};
use nix::errno::errno;
use nix::{ioctl_none, ioctl_write_int};

use crate::bpf::syscall::setns;
use crate::bpf::ProgramType;
use crate::error::OxidebpfError;
use crate::perf::constant::perf_flag::PERF_FLAG_FD_CLOEXEC;
use crate::perf::constant::{
    PERF_PATH, PMU_KRETPROBE_FILE, PMU_KTYPE_FILE, PMU_TTYPE_FILE, PMU_URETPROBE_FILE,
    PMU_UTYPE_FILE,
};
use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};
use std::io::Write;

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

fn enter_mount_ns(pid: pid_t) -> Result<RawFd, OxidebpfError> {
    let new_mnt = std::fs::File::open(format!("/proc/{}/ns/mnt", pid))
        .map_err(|_| OxidebpfError::FileIOError)?;
    let my_mnt =
        std::fs::File::open("/proc/self/ns/mnt").map_err(|_| OxidebpfError::FileIOError)?;

    if new_mnt
        .metadata()
        .map_err(|_| OxidebpfError::FileIOError)?
        .st_ino()
        == my_mnt
            .metadata()
            .map_err(|_| OxidebpfError::FileIOError)?
            .st_ino()
    {
        return Err(OxidebpfError::SelfTrace);
    }

    setns(new_mnt.into_raw_fd(), CLONE_NEWNS)?;

    Ok(my_mnt.into_raw_fd())
}

fn exit_mount_ns(ns_fd: RawFd) -> Result<(), OxidebpfError> {
    setns(ns_fd, CLONE_NEWNS)?;
    unsafe {
        if libc::close(ns_fd as c_int) < 0 {
            Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())))
        } else {
            Ok(())
        }
    }
}

// TODO: refactor
pub(crate) fn perf_event_open_debugfs(
    pid: pid_t,
    event_type: ProgramType,
    event_name: &str,
    offset: u64,
    func_name_or_path: &str,
) -> Result<String, OxidebpfError> {
    let prefix = match event_type {
        ProgramType::Kprobe => "kprobe",
        ProgramType::Kretprobe => "kprobe",
        ProgramType::Uprobe => "uprobe",
        ProgramType::Uretprobe => "uprobe",
        _ => return Err(OxidebpfError::UnsupportedEventType),
    };

    let event_path = format!("/sys/kernel/debug/tracing/{}_events", prefix);
    let mut event_file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(event_path)
        .map_err(|e| OxidebpfError::FileIOError)?;

    let event_alias = format!("{}_oxidebpf_{}", event_name, std::process::id());
    let mut ns_fd: RawFd = -1;
    let name = match event_type {
        ProgramType::Kprobe => {
            if offset > 0 {
                format!("p:kprobes/{} {}+{}", event_alias, func_name_or_path, offset)
            } else {
                format!("p:kprobes/{} {}", event_alias, func_name_or_path)
            }
        }
        // no maxactive support
        ProgramType::Kretprobe => {
            format!("r:kprobes/{} {}", event_alias, func_name_or_path)
        }
        ProgramType::Uprobe => {
            ns_fd = enter_mount_ns(pid)?;
            format!(
                "p:uprobe/{} {}:0x{}",
                event_alias, func_name_or_path, offset
            )
        }
        ProgramType::Uretprobe => {
            ns_fd = enter_mount_ns(pid)?;
            format!(
                "r:uretprobe/{} {}:0x{}",
                event_alias, func_name_or_path, offset
            )
        }
        _ => return Err(OxidebpfError::UnsupportedEventType),
    };

    event_file
        .write(name.as_bytes())
        .map_err(|_| OxidebpfError::FileIOError)?;

    match event_type {
        ProgramType::Uprobe | ProgramType::Uretprobe => {
            if ns_fd < 0 {
                // This should be impossible to reach
                return Err(OxidebpfError::UncaughtMountNsError);
            }
            exit_mount_ns(ns_fd)?;
        }
        _ => {}
    }

    Ok(format!(
        "/sys/kernel/debug/tracing/events/{}/{}",
        event_type, event_alias
    ))
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
    if !((*PERF_PATH).as_path().exists()) {
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
pub(crate) fn perf_event_ioc_set_bpf(perf_fd: RawFd, data: u32) -> Result<i32, OxidebpfError> {
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

fn perf_attach_tracepoint_with_debugfs(
    prog_fd: RawFd,
    event_path: String,
    cpu: i32,
) -> Result<i32, OxidebpfError> {
    let p_type = std::fs::read_to_string((*PMU_TTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .parse::<u32>()
        .map_err(|_| OxidebpfError::FileIOError)?;
    let config = std::fs::read_to_string(format!("{}/id", event_path))
        .map_err(|_| OxidebpfError::FileIOError)?
        .parse::<u64>()
        .map_err(|_| OxidebpfError::FileIOError)?;
    let perf_event_attr = PerfEventAttr {
        sample_union: PerfSample { sample_period: 1 },
        wakeup_union: PerfWakeup { wakeup_events: 1 },
        config,
        p_type,
        ..Default::default()
    };

    let pfd = perf_event_open(&perf_event_attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC)?;
    perf_attach_tracepoint(prog_fd, pfd)
}

fn perf_attach_tracepoint(prog_fd: RawFd, perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    perf_event_ioc_set_bpf(perf_fd, prog_fd as u32)?;
    perf_event_ioc_enable(perf_fd)
}

fn perf_event_with_probe(
    attach_point: &str,
    return_bit: u64,
    p_type: u32,
    offset: u64,
    cpu: i32,
) -> Result<RawFd, OxidebpfError> {
    let perf_event_attr = PerfEventAttr {
        sample_union: PerfSample { sample_period: 1 },
        wakeup_union: PerfWakeup { wakeup_events: 1 },
        bp_addr_union: PerfBpAddr {
            config1: attach_point.as_ptr() as u64,
        },
        bp_len_union: PerfBpLen { config2: offset },
        config: return_bit,
        p_type,
        ..Default::default()
    };
    perf_event_open(&perf_event_attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC)
}

pub(crate) fn attach_uprobe(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
    pid: pid_t,
) -> Result<i32, OxidebpfError> {
    let config = std::fs::read_to_string((*PMU_URETPROBE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?;
    let mut return_bit = 0u64;
    if config.contains("config:") {
        let bit = &config[6..]
            .parse::<u64>()
            .map_err(|_| OxidebpfError::FileIOError)?;
        if is_return {
            return_bit |= 1 << bit;
        }
    } else {
        return Err(OxidebpfError::FileIOError);
    }

    let p_type = std::fs::read_to_string((*PMU_UTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .parse::<u32>()
        .map_err(|_| OxidebpfError::FileIOError)?;

    match perf_event_with_probe(attach_point, return_bit, p_type, offset.unwrap_or(0), cpu) {
        Ok(pfd) => perf_attach_tracepoint(fd, pfd),
        Err(e) => {
            let event_path = perf_event_open_debugfs(
                pid,
                if is_return {
                    ProgramType::Uretprobe
                } else {
                    ProgramType::Uprobe
                },
                "",
                offset.unwrap_or(0),
                attach_point,
            )?;
            perf_attach_tracepoint_with_debugfs(fd, event_path, cpu)
        }
    }
}

pub(crate) fn attach_kprobe(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
) -> Result<i32, OxidebpfError> {
    let config = std::fs::read_to_string((*PMU_KRETPROBE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?;
    let mut return_bit = 0u64;
    if config.contains("config:") {
        let bit = &config[6..]
            .parse::<u64>()
            .map_err(|_| OxidebpfError::FileIOError)?;
        if is_return {
            return_bit |= 1 << bit;
        }
    } else {
        return Err(OxidebpfError::FileIOError);
    }

    let p_type = std::fs::read_to_string((*PMU_KTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .parse::<u32>()
        .map_err(|_| OxidebpfError::FileIOError)?;

    // create perf
    match perf_event_with_probe(attach_point, return_bit, p_type, offset.unwrap_or(0), cpu) {
        Ok(pfd) => perf_attach_tracepoint(fd, pfd),
        Err(e) => {
            let event_path = perf_event_open_debugfs(
                -1,
                if is_return {
                    ProgramType::Kretprobe
                } else {
                    ProgramType::Kprobe
                },
                "",
                offset.unwrap_or(0),
                attach_point,
            )?;
            perf_attach_tracepoint_with_debugfs(fd, event_path, cpu)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;

    use crate::bpf::syscall::tests::bpf_panic_error;
    use crate::perf::syscall::{perf_event_ioc_set_bpf, perf_event_open};
    use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};

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
