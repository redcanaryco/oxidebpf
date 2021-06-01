use std::convert::TryInto;
use std::fs::OpenOptions;
use std::os::raw::c_ulong;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use lazy_static::lazy_static;
use libc::pid_t;
use libc::{syscall, SYS_perf_event_open};
use nix::errno::errno;
use nix::{ioctl_none, ioctl_write_int};

use crate::bpf::ProgramType;
use crate::error::OxidebpfError;
use crate::perf::constant::perf_flag::PERF_FLAG_FD_CLOEXEC;
use crate::perf::constant::{
    PERF_PATH, PMU_KRETPROBE_FILE, PMU_KTYPE_FILE, PMU_TTYPE_FILE, PMU_URETPROBE_FILE,
    PMU_UTYPE_FILE,
};
use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};

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

pub(crate) fn perf_event_open_debugfs(
    attr: &PerfEventAttr,
    pid: pid_t,
    cpu: i32,
    group_fd: RawFd,
    flags: c_ulong,
    event_type: ProgramType,
    ev_name: String,
    offset: u64,
) -> Result<&str, OxidebpfError> {
    // redbpf/bpf-sys/bcc/libbpf.c:934 create_probe_event()
    let prefix = match event_type {
        ProgramType::Kprobe => "kprobe",
        ProgramType::Kretprobe => "kprobe",
        ProgramType::Uprobe => "uprobe",
        ProgramType::Uretprobe => "uprobe",
        _ => return Err(OxidebpfError::UnsupportedEventType),
    };

    let event_path = format!("/sys/kernel/debug/tracing/{}_events", prefix);
    let event_file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(event_path)
        .map_err(|e| OxidebpfError::FileIOError)?;

    let ev_alias = format!("{}_oxidebpf_{}", ev_name, std::process::id());
    let config = "TODO: fix";

    //   if (is_kprobe) {
    //     if (offset > 0 && attach_type == BPF_PROBE_ENTRY)
    //       snprintf(buf, PATH_MAX, "p:kprobes/%s %s+%"PRIu64,
    //                ev_alias, config1, offset);
    //     else if (maxactive > 0 && attach_type == BPF_PROBE_RETURN)
    //       snprintf(buf, PATH_MAX, "r%d:kprobes/%s %s",
    //                maxactive, ev_alias, config1);
    //     else
    //       snprintf(buf, PATH_MAX, "%c:kprobes/%s %s",
    //                attach_type == BPF_PROBE_ENTRY ? 'p' : 'r',
    //                ev_alias, config1);
    //   } else {
    //     res = snprintf(buf, PATH_MAX, "%c:%ss/%s %s:0x%lx", attach_type==BPF_PROBE_ENTRY ? 'p' : 'r',
    //                    event_type, ev_alias, config1, (unsigned long)offset);
    //     if (res < 0 || res >= PATH_MAX) {
    //       fprintf(stderr, "Event alias (%s) too long for buffer\n", ev_alias);
    //       close(kfd);
    //       return -1;
    //     }
    //     ns_fd = enter_mount_ns(pid);
    //   }

    let name = match event_type {
        ProgramType::Kprobe => {
            format!("p:kprobes/{} {}+{}", ev_alias, config, offset)
        }
        // no maxactive support
        ProgramType::Kretprobe => {
            format!("r{}:kprobes/{} {}", 0, ev_alias, config)
        }
        ProgramType::Uprobe => {
            format!("p:{}/{} {}:0x{}", prefix, ev_alias, config, offset)
            // enter mount pid?
        }
        ProgramType::Uretprobe => {
            format!("r:{}/{} {}:0x{}", prefix, ev_alias, config, offset)
            // enter mount pid?
        }
        _ => return Err(OxidebpfError::UnsupportedEventType),
    };

    //
    //   if (write(kfd, buf, strlen(buf)) < 0) {
    //     if (errno == ENOENT)
    //       fprintf(stderr, "cannot attach %s, probe entry may not exist\n", event_type);
    //     else
    //       fprintf(stderr, "cannot attach %s, %s\n", event_type, strerror(errno));
    //     close(kfd);
    //     goto error;
    //   }
    //   close(kfd);
    //   if (!is_kprobe)
    //     exit_mount_ns(ns_fd);
    //   snprintf(buf, PATH_MAX, "/sys/kernel/debug/tracing/events/%ss/%s",
    //            event_type, ev_alias);
    //   return 0;
    // error:
    //   if (!is_kprobe)
    //     exit_mount_ns(ns_fd);
    //   return -1;

    Ok("event_path")
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
    event_path: &str,
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
            let perf_event_attr = PerfEventAttr {
                ..Default::default()
            };
            let event_path = perf_event_open_debugfs(
                &perf_event_attr,
                0,
                0,
                -1,
                0,
                ProgramType::Unspec,
                "".to_string(),
                0,
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
            let perf_event_attr = PerfEventAttr {
                ..Default::default()
            };
            let event_path = perf_event_open_debugfs(
                &perf_event_attr,
                0,
                0,
                -1,
                0,
                ProgramType::Unspec,
                "".to_string(),
                0,
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
