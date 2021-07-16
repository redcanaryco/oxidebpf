use std::convert::TryInto;

use std::io::Write;
use std::os::linux::fs::MetadataExt;
use std::os::raw::{c_int, c_ulong};
use std::os::unix::io::{IntoRawFd, RawFd};

use libc::pid_t;
use libc::{syscall, SYS_perf_event_open, SYS_setns, CLONE_NEWNS};
use nix::errno::errno;
use nix::{ioctl_none, ioctl_write_int};

use crate::error::OxidebpfError;
use crate::perf::constant::perf_flag::PERF_FLAG_FD_CLOEXEC;

// the compiler doesn't recognize that these _are_ used
#[allow(unused_imports)]
use crate::perf::constant::{
    PERF_PATH, PMU_KRETPROBE_FILE, PMU_KTYPE_FILE, PMU_TTYPE_FILE, PMU_URETPROBE_FILE,
    PMU_UTYPE_FILE,
};

use crate::perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};
use crate::ProgramType;
use std::ffi::CString;

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

fn my_mount_fd() -> Result<RawFd, OxidebpfError> {
    let my_mnt =
        std::fs::File::open("/proc/self/ns/mnt").map_err(|_| OxidebpfError::FileIOError)?;
    Ok(my_mnt.into_raw_fd())
}

fn enter_pid_mnt_ns(pid: pid_t, my_mount: RawFd) -> Result<usize, OxidebpfError> {
    let new_mnt = std::fs::File::open(format!("/proc/{}/ns/mnt", pid))
        .map_err(|_| OxidebpfError::FileIOError)?;
    let new_inode = new_mnt
        .metadata()
        .map_err(|_| OxidebpfError::FileIOError)?
        .st_ino();
    let my_inode = nix::sys::stat::fstat(my_mount)
        .map_err(|_| OxidebpfError::FileIOError)?
        .st_ino;
    if new_inode == my_inode {
        return Err(OxidebpfError::SelfTrace);
    }

    setns(new_mnt.into_raw_fd(), CLONE_NEWNS)
}

fn restore_mnt_ns(original_mnt_ns_fd: RawFd) -> Result<(), OxidebpfError> {
    setns(original_mnt_ns_fd, CLONE_NEWNS)?;
    unsafe {
        if libc::close(original_mnt_ns_fd as c_int) < 0 {
            Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn perf_event_open_debugfs(
    pid: pid_t,
    event_type: ProgramType,
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
        .map_err(|_e| OxidebpfError::FileIOError)?;

    let mut uuid = uuid::Uuid::new_v4().to_string();
    uuid.truncate(8);
    let event_alias = format!("oxidebpf_{}", uuid);
    let mut my_fd: RawFd = -1;
    let name = match event_type {
        ProgramType::Kprobe => {
            if offset > 0 {
                format!("p:kprobe/{} {}+{}", event_alias, func_name_or_path, offset)
            } else {
                format!("p:kprobe/{} {}", event_alias, func_name_or_path)
            }
        }
        // no maxactive support for now
        ProgramType::Kretprobe => {
            format!("r:kprobe/{} {}", event_alias, func_name_or_path)
        }
        ProgramType::Uprobe => {
            my_fd = my_mount_fd()?;
            enter_pid_mnt_ns(pid, my_fd)?;
            format!(
                "p:uprobe/{} {}:0x{}",
                event_alias, func_name_or_path, offset
            )
        }
        ProgramType::Uretprobe => {
            my_fd = my_mount_fd()?;
            enter_pid_mnt_ns(pid, my_fd)?;
            format!(
                "r:uretprobe/{} {}:0x{}",
                event_alias, func_name_or_path, offset
            )
        }
        _ => return Err(OxidebpfError::UnsupportedEventType),
    };

    event_file
        .write(format!("{}\n", name).as_bytes())
        .map_err(|_| OxidebpfError::FileIOError)?;

    match event_type {
        ProgramType::Uprobe | ProgramType::Uretprobe => {
            if my_fd < 0 {
                // This should be impossible to reach
                return Err(OxidebpfError::UncaughtMountNsError);
            }
            restore_mnt_ns(my_fd)?;
        }
        _ => {}
    }

    Ok(format!("{}/{}", event_type, event_alias))
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
    let ptr: *const PerfEventAttr = attr;

    let ret = unsafe {
        syscall(
            (SYS_perf_event_open as i32).into(),
            ptr,
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
    #![allow(clippy::useless_conversion, clippy::redundant_closure)] // fails to compile otherwise
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
    #![allow(clippy::redundant_closure)]
    unsafe { u_perf_event_ioc_enable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
}

/// Safe wrapper around `u_perf_event_ioc_disable()`
pub(crate) fn perf_event_ioc_disable(perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    #![allow(clippy::redundant_closure)]
    unsafe { u_perf_event_ioc_disable(perf_fd).map_err(|e| OxidebpfError::PerfIoctlError(e)) }
}

fn perf_attach_tracepoint_with_debugfs(
    prog_fd: RawFd,
    event_path: String,
    cpu: i32,
) -> Result<String, OxidebpfError> {
    let p_type = std::fs::read_to_string((*PMU_TTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .trim()
        .to_string()
        .parse::<u32>()
        .map_err(|_| OxidebpfError::NumberParserError)?;

    let config = std::fs::read_to_string(format!(
        "/sys/kernel/debug/tracing/events/{}/id",
        event_path
    ))
    .map_err(|_| OxidebpfError::FileIOError)?
    .trim()
    .to_string()
    .parse::<u64>()
    .map_err(|_| OxidebpfError::NumberParserError)?;

    let perf_event_attr = PerfEventAttr {
        sample_union: PerfSample { sample_period: 1 },
        wakeup_union: PerfWakeup { wakeup_events: 1 },
        config,
        p_type,
        ..Default::default()
    };

    let pfd = perf_event_open(&perf_event_attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC)?;
    perf_attach_tracepoint(prog_fd, pfd)?;
    Ok(event_path)
}

fn perf_attach_tracepoint(prog_fd: RawFd, perf_fd: RawFd) -> Result<i32, OxidebpfError> {
    perf_event_ioc_set_bpf(perf_fd, prog_fd as u32)?;
    perf_event_ioc_enable(perf_fd)
}

fn perf_event_with_attach_point(
    attach_point: &str,
    return_bit: u64,
    p_type: u32,
    offset: u64,
    cpu: i32,
    pid: Option<i32>,
) -> Result<RawFd, OxidebpfError> {
    #![allow(clippy::redundant_closure)]
    let ap_cstring =
        CString::new(attach_point).map_err(|e| OxidebpfError::CStringConversionError(e))?;
    let perf_event_attr = PerfEventAttr {
        sample_union: PerfSample { sample_period: 1 },
        wakeup_union: PerfWakeup { wakeup_events: 1 },
        bp_addr_union: PerfBpAddr {
            config1: ap_cstring.as_ptr() as u64,
        },
        bp_len_union: PerfBpLen { config2: offset },
        config: return_bit,
        p_type,
        ..Default::default()
    };
    perf_event_open(
        &perf_event_attr,
        pid.unwrap_or(-1),
        cpu,
        -1,
        PERF_FLAG_FD_CLOEXEC,
    )
}

pub(crate) fn attach_uprobe_debugfs(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
    pid: pid_t,
) -> Result<String, OxidebpfError> {
    let event_path = perf_event_open_debugfs(
        pid,
        if is_return {
            ProgramType::Uretprobe
        } else {
            ProgramType::Uprobe
        },
        offset.unwrap_or(0),
        attach_point,
    )?;
    perf_attach_tracepoint_with_debugfs(fd, event_path, cpu)
}

pub(crate) fn attach_uprobe(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
    pid: pid_t,
) -> Result<RawFd, OxidebpfError> {
    let config = std::fs::read_to_string((*PMU_URETPROBE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?;

    let mut return_bit = 0u64;
    if config.contains("config:") {
        let bit = &config[7..]
            .trim()
            .to_string()
            .parse::<u64>()
            .map_err(|_| OxidebpfError::NumberParserError)?;
        if is_return {
            return_bit |= 1 << bit;
        }
    } else {
        return Err(OxidebpfError::FileIOError);
    }

    let p_type = std::fs::read_to_string((*PMU_UTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .trim()
        .to_string()
        .parse::<u32>()
        .map_err(|_| OxidebpfError::NumberParserError)?;

    let pfd = perf_event_with_attach_point(
        attach_point,
        return_bit,
        p_type,
        offset.unwrap_or(0),
        cpu,
        Some(pid),
    )?;
    perf_attach_tracepoint(fd, pfd)
}

pub(crate) fn attach_kprobe_debugfs(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
) -> Result<String, OxidebpfError> {
    let event_path = perf_event_open_debugfs(
        -1,
        if is_return {
            ProgramType::Kretprobe
        } else {
            ProgramType::Kprobe
        },
        offset.unwrap_or(0),
        attach_point,
    )?;

    match perf_attach_tracepoint_with_debugfs(fd, event_path.clone(), cpu.clone()) {
        Err(OxidebpfError::FileIOError) => {
            if is_return {
                // depending on the kernel version, we may need to have either `kprobe`
                // or `kretprobe` as the path
                let new_path = event_path.replace("kretprobe", "kprobe");
                perf_attach_tracepoint_with_debugfs(fd, new_path, cpu)
            } else {
                Err(OxidebpfError::FileIOError)
            }
        }
        Ok(v) => Ok(v),
        Err(e) => Err(e),
    }
}

pub(crate) fn attach_kprobe(
    fd: RawFd,
    attach_point: &str,
    is_return: bool,
    offset: Option<u64>,
    cpu: i32,
) -> Result<RawFd, OxidebpfError> {
    let config = std::fs::read_to_string((*PMU_KRETPROBE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?;
    let mut return_bit = 0u64;

    if config.contains("config:") {
        let bit = &config[7..]
            .trim()
            .to_string()
            .parse::<u64>()
            .map_err(|_| OxidebpfError::NumberParserError)?;
        if is_return {
            return_bit |= 1 << bit;
        }
    } else {
        return Err(OxidebpfError::FileIOError);
    }

    let p_type = std::fs::read_to_string((*PMU_KTYPE_FILE).as_path())
        .map_err(|_| OxidebpfError::FileIOError)?
        .trim()
        .to_string()
        .parse::<u32>()
        .map_err(|_| OxidebpfError::NumberParserError)?;

    let pfd = perf_event_with_attach_point(
        attach_point,
        return_bit,
        p_type,
        offset.unwrap_or(0),
        cpu,
        None,
    )?;
    perf_attach_tracepoint(fd, pfd)
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

#[cfg(test)]
mod tests {
    use crate::perf::constant::PMU_KTYPE_FILE;

    use crate::blueprint::ProgramBlueprint;
    use crate::bpf::constant::bpf_prog_type::BPF_PROG_TYPE_KPROBE;
    use crate::bpf::syscall::bpf_prog_load;
    use crate::error::OxidebpfError;
    use crate::perf::constant::{perf_event_sample_format, perf_sw_ids, perf_type_id};
    use crate::perf::syscall::{
        perf_attach_tracepoint_with_debugfs, perf_event_ioc_disable, perf_event_ioc_enable,
        perf_event_ioc_set_bpf, perf_event_open, perf_event_open_debugfs,
        perf_event_with_attach_point,
    };
    use crate::perf::{PerfEventAttr, PerfSample, PerfWakeup};
    use crate::ProgramType;
    use lazy_static::lazy_static;
    use std::fs;
    use std::os::unix::io::RawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    lazy_static! {
        static ref EVENT_ATTR: PerfEventAttr = PerfEventAttr {
            config: perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as u64,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            p_type: perf_type_id::PERF_TYPE_SOFTWARE,
            sample_type: perf_event_sample_format::PERF_SAMPLE_RAW as u64,
            sample_union: PerfSample { sample_period: 1 },
            wakeup_union: PerfWakeup { wakeup_events: 1 },
            ..Default::default()
        };
    }

    fn ctrlc_wait() {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("Error setting handler");
        while running.load(Ordering::SeqCst) {}
    }

    #[test]
    fn test_perf_event_open() {
        perf_event_open(&EVENT_ATTR, -1, 0, -1, 0).unwrap();
    }

    #[test]
    fn test_perf_event_ioc_set_bpf() {
        let blueprint = ProgramBlueprint::new(
            fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("test")
                    .join(format!("test_program_{}", std::env::consts::ARCH)),
            )
            .expect("Could not open test program")
            .as_slice(),
            None,
        )
        .unwrap();

        let program_object = blueprint.programs.get("test_program").unwrap();
        let prog_fd = bpf_prog_load(
            BPF_PROG_TYPE_KPROBE,
            &program_object.code,
            program_object.license.clone(),
            program_object.kernel_version,
        )
        .expect("Could not load test program");
        let p_type = std::fs::read_to_string((*PMU_KTYPE_FILE).as_path())
            .unwrap_or("6".to_string()) // when using debugfs
            .trim()
            .to_string()
            .parse::<u32>()
            .unwrap();

        let fd_or_name: Result<(Option<String>, Option<RawFd>), OxidebpfError> =
            match perf_event_with_attach_point("do_mount", 0, p_type.clone(), 0, 0, None) {
                Ok(fd) => Ok((None, Some(fd))),
                Err(_e) => {
                    let event_path =
                        perf_event_open_debugfs(-1, ProgramType::Kprobe, 0, "do_mount").unwrap();
                    // perf_event_ioc_set_bpf is called in here already
                    let s = perf_attach_tracepoint_with_debugfs(prog_fd, event_path, 0).unwrap();
                    Ok((Some(s), None))
                }
            };
        match fd_or_name {
            Ok((None, Some(fd))) => {
                perf_event_ioc_set_bpf(fd, prog_fd as u32).unwrap();
            }
            _ => {}
        }
    }

    #[test]
    fn test_perf_event_ioc_enable() {
        let pfd = perf_event_open(&EVENT_ATTR, -1, 0, -1, 0).unwrap();
        perf_event_ioc_enable(pfd).unwrap();
    }

    #[test]
    fn test_perf_event_ioc_disable() {
        let event_attr = PerfEventAttr {
            config: perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as u64,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            p_type: perf_type_id::PERF_TYPE_SOFTWARE,
            sample_type: perf_event_sample_format::PERF_SAMPLE_RAW as u64,
            sample_union: PerfSample { sample_period: 1 },
            wakeup_union: PerfWakeup { wakeup_events: 1 },
            ..Default::default()
        };
        let pfd = perf_event_open(&event_attr, -1, 0, -1, 0).unwrap();
        perf_event_ioc_enable(pfd).unwrap();
        perf_event_ioc_disable(pfd).unwrap();
    }
}
