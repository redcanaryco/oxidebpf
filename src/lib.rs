//! A permissive library for managing eBPF programs.
//!
//! `oxidebpf` allows a user to easily manage a pre-built eBPF object file, creating
//! groups of programs based on functionality and loading them as units.
//! For a quick getting-started, see the documentation for [`ProgramGroup`](struct@ProgramGroup)'s
//! `new()` and `load()` functions.
//!
//! Note: by default, `oxidebpf` will load BPF programs with logging disabled. If you
//! wish to enable logging, enable the `log_buf` feature. If the
//! default log size (4096) is not large enough to hold the verifier's logs, the load
//! will fail. If you need more space, `oxidebpf` will pull a log size in bytes from the
//! `LOG_SIZE` environment variable (e.g., `LOG_SIZE=8192 ./my_program`).
#![allow(dead_code)]

mod blueprint;
mod bpf;
mod cpu_info;
mod debugfs;
mod error;
mod maps;
mod perf;
mod program_group;
mod program_version;

pub use blueprint::{ProgramBlueprint, SectionType};
pub use error::OxidebpfError;
pub use maps::{ArrayMap, BpfHashMap, RWMap};
pub use program_group::ProgramGroup;
pub use program_version::{PerfBufferSize, ProgramVersion};

use perf::syscall::{attach_kprobe, attach_kprobe_debugfs, attach_uprobe, attach_uprobe_debugfs};

use std::{
    fmt::{self, Display, Formatter},
    format,
    os::unix::io::RawFd,
};

use lazy_static::lazy_static;
use libc::pid_t;
use slog::{info, o, Logger};
use slog_atomic::{AtomicSwitch, AtomicSwitchCtrl};

lazy_static! {
    /// The slog Logger for the oxidebpf library. You can change the destination
    /// by accessing the drain control with `LOGGER.1.set(your_new_drain)`.
    pub static ref LOGGER: (Logger, AtomicSwitchCtrl) = create_slogger_root();
}

fn create_slogger_root() -> (slog::Logger, AtomicSwitchCtrl) {
    let drain = slog::Logger::root(slog::Discard, o!());
    let drain = AtomicSwitch::new(drain);
    (slog::Logger::root(drain.clone(), o!()), drain.ctrl())
}

#[cfg(target_arch = "aarch64")]
const ARCH_SYSCALL_PREFIX: &str = "__arm64_";
#[cfg(target_arch = "x86_64")]
const ARCH_SYSCALL_PREFIX: &str = "__x64_";

#[repr(C)]
#[derive(Debug, Default)]
pub struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Message format for messages sent back across the channel
///
/// Messages could either be dropped in case of messages lost, usually
/// caused by a a filled up perf buffer, or an event with source and
/// data
#[derive(Debug)]
pub enum PerfChannelMessage {
    /// A count of how many messages were lost
    Dropped(u64),
    /// A received message with information about its source
    Event {
        /// The name of the map this message is from.
        map_name: String,
        /// The cpuid of the CPU this message is from.
        cpuid: i32,
        /// The data in the message.
        data: Vec<u8>,
    },
}

/// Enum describing how a [ProgramGroup](struct@ProgramBlueprint) handles
/// auto-mounting debugfs.
#[derive(Clone)]
pub enum DebugfsMountOpts {
    /// Do not mount debugfs at all.
    MountDisabled,
    /// Mount debugfs to the conventional location (`/sys/kernel/debug`).
    MountConventional,
    /// Mount debugfs to a custom location.
    MountCustom(String),
}

impl Default for DebugfsMountOpts {
    fn default() -> Self {
        DebugfsMountOpts::MountDisabled
    }
}

impl From<&str> for DebugfsMountOpts {
    fn from(value: &str) -> Self {
        DebugfsMountOpts::MountCustom(value.to_string())
    }
}

impl From<Option<&str>> for DebugfsMountOpts {
    fn from(value: Option<&str>) -> DebugfsMountOpts {
        match value {
            Some(v) => v.into(),
            None => DebugfsMountOpts::MountDisabled,
        }
    }
}

/// Different Linux scheduling policies, intended to be paired with a priority number in the
/// builder function [`polling_thread_priority`](fn@polling_thread_priority) of
/// [`ProgramGroup`](struct@ProgramGroup).
#[derive(Clone, Copy)]
pub enum SchedulingPolicy {
    /// The default Linux scheduling technique. When paired with a priority number, the
    /// priority number will be interpreted as a niceness value (-20 to 19, inclusive).
    Other(i8),
    /// The lowest possible priority on the system. This cannot be modified by a niceness value,
    /// and provided numbers will be ignored.
    Idle,
    /// Similar to Other, except the scheduler will always assume this thread is CPU-intensive
    /// for scheduling purposes. Any provided priority number will be interpreted as a niceness
    /// value (-20 to 19, inclusive).
    Batch(i8),
    /// Use first-in-first-out scheduling for this thread. The provided priority value will be
    /// the thread's overall priority (0 to 99, inclusive). Note that the polling thread will not
    /// be preempted (unless by a higher priority process) when using this policy, until it
    /// finishes processing a batch and blocks on polling.
    FIFO(u8),
    /// A Round-Robin modification of the FIFO scheduling policy that preempts the process after
    /// reaching some maximum time quantum limit, and puts it at the back of the queue. The provided
    /// priority should be the same as FIFO (0 to 99, inclusive).
    RR(u8),
    /// The deadline policy attempts to finish periodic jobs by a certain deadline. It takes
    /// three numbers: the job's expected runtime, the job's deadline time, and
    /// the job's period, all in nanoseconds. See the following diagram from the `sched`
    /// manpage:
    ///
    /// ```text
    ///  arrival/wakeup                    absolute deadline
    ///       |    start time                    |
    ///       |        |                         |
    ///       v        v                         v
    ///  -----x--------xooooooooooooooooo--------x--------x---
    ///                |<-- Runtime ------->|
    ///       |<----------- Deadline ----------->|
    ///       |<-------------- Period ------------------->|
    /// ```
    ///
    /// The provided priority number will be interpreted as the estimated runtime, the deadline,
    /// and the period (the kernel enforces runtime <= deadline <= period).
    Deadline(u64, u64, u64),
}

impl From<SchedulingPolicy> for thread_priority::ThreadSchedulePolicy {
    fn from(policy: SchedulingPolicy) -> Self {
        match policy {
            SchedulingPolicy::Other(_) => thread_priority::ThreadSchedulePolicy::Normal(
                thread_priority::NormalThreadSchedulePolicy::Other,
            ),
            SchedulingPolicy::Idle => thread_priority::ThreadSchedulePolicy::Normal(
                thread_priority::NormalThreadSchedulePolicy::Idle,
            ),
            SchedulingPolicy::Batch(_) => thread_priority::ThreadSchedulePolicy::Normal(
                thread_priority::NormalThreadSchedulePolicy::Batch,
            ),
            SchedulingPolicy::FIFO(_) => thread_priority::ThreadSchedulePolicy::Realtime(
                thread_priority::RealtimeThreadSchedulePolicy::Fifo,
            ),
            SchedulingPolicy::RR(_) => thread_priority::ThreadSchedulePolicy::Realtime(
                thread_priority::RealtimeThreadSchedulePolicy::RoundRobin,
            ),
            SchedulingPolicy::Deadline(_, _, _) => thread_priority::ThreadSchedulePolicy::Realtime(
                thread_priority::RealtimeThreadSchedulePolicy::Deadline,
            ),
        }
    }
}

// Processes scheduled under one of the real-time policies
// (SCHED_FIFO, SCHED_RR) have a sched_priority value in the range 1
// (low) to 99 (high).  For threads scheduled under one of the normal
// scheduling policies (SCHED_OTHER, SCHED_IDLE, SCHED_BATCH),
// sched_priority is not used in scheduling decisions (it must be
// specified as 0).
// <https://man7.org/linux/man-pages/man7/sched.7.html>
impl From<SchedulingPolicy> for thread_priority::ThreadPriority {
    fn from(policy: SchedulingPolicy) -> Self {
        match policy {
            SchedulingPolicy::Other(_) | SchedulingPolicy::Idle | SchedulingPolicy::Batch(_) => {
                thread_priority::ThreadPriority::from_posix(thread_priority::ScheduleParams {
                    sched_priority: 0,
                })
            }
            SchedulingPolicy::FIFO(polling_priority) | SchedulingPolicy::RR(polling_priority) => {
                thread_priority::ThreadPriority::from_posix(thread_priority::ScheduleParams {
                    sched_priority: polling_priority.clamp(1_u8, 99_u8) as i32,
                })
            }
            SchedulingPolicy::Deadline(r, d, p) => {
                thread_priority::ThreadPriority::Deadline(r, d, p)
            }
        }
    }
}

#[derive(Clone, Default)]
struct TailCallMapping {
    map: String,
    index: u32,
}

/// The description of an individual eBPF program. Note: This is _not_ the same
/// as the eBPF program itself, the actual binary is loaded from a
/// [`ProgramBlueprint`](struct@ProgramBlueprint).
#[derive(Clone, Default)]
pub struct Program<'a> {
    kind: Option<ProgramType>,
    name: &'a str,
    attach_points: Vec<String>,
    optional: bool,
    loaded: bool,
    is_syscall: bool,
    fd: RawFd,
    pid: Option<pid_t>,
    tail_call_mapping: Option<TailCallMapping>,
    debugfs_mount: DebugfsMountOpts,
}

impl<'a> Program<'a> {
    /// Create a new program specification.
    ///
    /// You must provide the program type, the name of the program section in your
    /// blueprint's object file (see ['ProgramBlueprint'](struct@ProgramBlueprint))
    /// and a vector of attachment points.
    ///
    /// # Note
    ///
    /// If your blueprint contains duplicate names or if you provide multiple `Program`s
    /// with the same specified blueprint program, the loader will attempt to pairwise
    /// load all combinations. For example, if you have two programs `kprobe/program` and
    /// `kretprobe/program` and give the `ProgramVersion` two `Program` objects, both with
    /// program `program`, then the loader will attempt to load and attach each probe twice.
    /// To avoid this, give the programs in your ELF binary unique names.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::{Program, ProgramType};
    ///
    /// Program::new(
    ///     "sys_ptrace_write",
    ///     &["do_mount"],
    /// ).optional(false).syscall(true);
    /// ```
    pub fn new(name: &'a str, attach_points: &[&str]) -> Program<'a> {
        Self {
            kind: None,
            name,
            attach_points: attach_points.iter().map(|ap| ap.to_string()).collect(),
            optional: false,
            loaded: false,
            is_syscall: false,
            fd: -1,
            pid: None,
            tail_call_mapping: None,
            debugfs_mount: DebugfsMountOpts::MountDisabled,
        }
    }

    /// Specify a pid to attach to, if this program should trace a specific pid.
    ///
    /// The pid is mainly used for uprobes.
    pub fn pid(mut self, pid: pid_t) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Specify whether or not the program is optional to load.
    ///
    /// If the `Program` is optional then any encapsulating `ProgramVersion`
    /// will ignore any errors when attempting to load or attach it.
    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    /// Specify whether or not the program is tracing a syscall.
    ///
    /// The `syscall` setting is used to automatically discover syscall wrappers
    /// for the system we are running on. For example, if we want to trace `sys_ptrace`
    /// we may want to trace `__x64_sys_ptrace` instead. By setting `syscall(true)`,
    /// oxidebpf will attempt to discover and fix this for you, and you can simply pass
    /// `sys_ptrace` as the attachment point.
    pub fn syscall(mut self, syscall: bool) -> Self {
        self.is_syscall = syscall;
        self
    }

    /// Specify that the program should be loaded into the given tail call map at the given index.
    ///
    /// The `tail_call_index` argument is used to know which indices to insert programs
    /// at in the program's tail call map. The map that it is inserted into is the map with
    /// the given `map_name`. If no map exists with `map_name`, a runtime
    /// `OxidebpfError::MapNotFound` error will be thrown.
    ///
    /// # Example
    ///
    /// If another one of your programs will tail call into this program and expects it to
    /// exist at index 5, you should call this function with 5 as the argument.
    ///
    /// ```no_run
    /// use oxidebpf::Program;
    ///
    /// let program = Program::new(
    ///     "my_program", &["do_mount"]
    /// ).tail_call_map_index("my_map", 5);
    /// ```
    pub fn tail_call_map_index(mut self, map_name: &str, tail_call_index: u32) -> Self {
        self.tail_call_mapping = Some(TailCallMapping {
            map: map_name.to_string(),
            index: tail_call_index,
        });
        self
    }

    /// Optionally specify what type of program this is.
    ///
    /// If the type specified matches what is read from the ELF file, this has no effect. If
    /// the type specified is a different, but compatible, type (e.g., kprobe and kretprobe)
    /// then the type will be "switched" and the program will be loaded as the specified type.
    /// If the types are incompatible (e.g., kprobe vs uprobe), an attempt will be made to load
    /// the program as directed, but you will likely receive an error on loading or attaching.
    ///
    /// # Example
    ///
    /// This will tell the loader to attempt to load this program as a kretprobe, despite whatever
    /// it exists as in the ELF file.
    ///
    /// ```no_run
    /// use oxidebpf::{Program, ProgramType};
    ///
    /// let program = Program::new(
    ///    "my_program", &["do_mount"]
    /// ).program_type(ProgramType::Kretprobe);
    /// ```
    pub fn program_type(mut self, kind: ProgramType) -> Self {
        self.kind = Some(kind);
        self
    }

    fn set_debugfs_mount_point(&mut self, debugfs_mount: DebugfsMountOpts) {
        self.debugfs_mount = debugfs_mount
    }

    fn mount_debugfs_if_missing(&self) {
        let mount_point = match &self.debugfs_mount {
            DebugfsMountOpts::MountDisabled => {
                return;
            }
            DebugfsMountOpts::MountConventional => "/sys/kernel/debug",
            DebugfsMountOpts::MountCustom(value) => value.as_str(),
        };

        if let Err(mount_err) = debugfs::mount_if_missing(mount_point) {
            info!(LOGGER.0, "Failed to mount debugfs: {:?}", mount_err);
        }
    }

    fn attach_kprobe(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        let is_return = self.kind == Some(ProgramType::Kretprobe);

        self.attach_points
            .iter()
            .fold(Ok((vec![], vec![])), |mut result, attach_point| {
                match attach_kprobe(self.fd, attach_point, is_return, None, 0) {
                    Ok(fd) => {
                        // skip if we already failed
                        if let Ok((_, fds)) = &mut result {
                            fds.push(fd);
                        }
                    }
                    Err(e) => {
                        info!(LOGGER.0, "Program::attach_kprobe(); original error: {:?}", e);
                        self.mount_debugfs_if_missing();
                        match attach_kprobe_debugfs(self.fd, attach_point, is_return, None, 0) {
                            Ok((path, fd)) => {
                                // skip if we already failed
                                if let Ok((paths, fds)) = &mut result {
                                    paths.push(path);
                                    fds.push(fd);
                                }
                            }
                            Err(s) => match &mut result {
                                Ok(_) => result = Err(vec![e, s]),
                                Err(errors) => {
                                    info!(
                                        LOGGER.0,
                                        "Program::attach_kprobe(); multiple kprobe load errors: {:?}; {:?}", e, s
                                    );
                                    errors.extend(vec![e, s])
                                }
                            },
                        }
                    }
                }

                result
            })
            .map_err(OxidebpfError::MultipleErrors)
    }

    fn attach_uprobe(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        let is_return = self.kind == Some(ProgramType::Uretprobe);
        let pid = self.pid.unwrap_or(-1);

        cpu_info::online()?
            .into_iter()
            .flat_map(|cpu| {
                self.attach_points
                    .iter()
                    .map(move |attach_point| (cpu, attach_point))
            })
            .fold(Ok((vec![], vec![])), |mut result, (cpu, attach_point)| {
                match attach_uprobe(self.fd, attach_point, is_return, None, cpu, pid) {
                    Ok(fd) => {
                        // skip if we already failed
                        if let Ok((_, fds)) = &mut result {
                            fds.push(fd);
                        }
                    }
                    Err(e) => {
                        self.mount_debugfs_if_missing();
                        match attach_uprobe_debugfs(
                            self.fd,
                            attach_point,
                            is_return,
                            None,
                            cpu,
                            pid,
                        ) {
                            Ok((path, fd)) => {
                                // skip if we already failed
                                if let Ok((paths, fds)) = &mut result {
                                    paths.push(path);
                                    fds.push(fd);
                                }
                            }
                            Err(s) => match &mut result {
                                Ok(_) => result = Err(vec![e, s]),
                                Err(errors) => {
                                    info!(
                                        LOGGER.0,
                                        "Program::attach_uprobe(); multiple uprobe load errors: {:?}; {:?}", e, s
                                    );
                                    errors.extend(vec![e, s])
                                }
                            },
                        }
                    }
                }

                result
            })
            .map_err(OxidebpfError::MultipleErrors)
    }

    fn attach(&mut self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        match self.attach_probes() {
            Ok(res) => Ok(res),
            Err(e) => {
                if self.is_syscall {
                    self.attach_points
                        .iter_mut()
                        .for_each(|ap| *ap = format!("{}{}", ARCH_SYSCALL_PREFIX, ap));

                    self.attach_probes()
                } else {
                    info!(LOGGER.0, "Program::attach(); attach error: {:?}", e);
                    Err(e)
                }
            }
        }
    }

    fn attach_probes(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        if !self.loaded {
            info!(
                LOGGER.0,
                "Program::attach_probes(); attempting to attach probes while program not loaded"
            );
            return Err(OxidebpfError::ProgramNotLoaded);
        }

        match &self.kind {
            Some(ProgramType::Kprobe | ProgramType::Kretprobe) => self.attach_kprobe(),
            Some(ProgramType::Uprobe | ProgramType::Uretprobe) => self.attach_uprobe(),
            Some(t) => {
                info!(
                    LOGGER.0,
                    "Program::attach_probes(); attempting to load unsupported program type {:?}", t
                );
                Err(OxidebpfError::UnsupportedProgramType)
            }
            _ => {
                info!(
                    LOGGER.0,
                    "Program::attach_probes(); attempting to load unsupported program type: unknown"
                );
                Err(OxidebpfError::UnsupportedProgramType)
            }
        }
    }

    pub(crate) fn loaded_as(&mut self, fd: RawFd) {
        self.loaded = true;
        self.fd = fd;
    }

    fn set_fd(&mut self, fd: RawFd) {
        self.fd = fd
    }

    fn get_fd(&self) -> Result<RawFd, OxidebpfError> {
        if self.loaded {
            Ok(self.fd)
        } else {
            Err(OxidebpfError::ProgramNotLoaded)
        }
    }
}

pub fn set_memlock_limit(limit: usize) -> Result<(), OxidebpfError> {
    unsafe {
        let rlim = libc::rlimit {
            rlim_cur: limit as u64,
            rlim_max: limit as u64,
        };
        let ret = libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim as *const _);

        if ret < 0 {
            info!(
                LOGGER.0,
                "set_memlock_limit(); unable to set memlock limit, errno: {}",
                nix::errno::errno()
            );
            Err(OxidebpfError::LinuxError(
                "set_memlock_limit".to_string(),
                nix::errno::Errno::from_i32(nix::errno::errno()),
            ))
        } else {
            Ok(())
        }
    }
}

/// Return the current process capabilities header and set.
pub fn get_capabilities() -> Result<(CapUserHeader, CapUserData), OxidebpfError> {
    let mut hdrp = CapUserHeader {
        version: 0x20080522, // version 3
        pid: 0,              // calling process
    };

    let mut datap = CapUserData::default();

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdrp as *mut _ as *mut libc::c_void,
            &mut datap as *mut _ as *mut libc::c_void,
        )
    };

    if ret < 0 {
        Err(OxidebpfError::LinuxError(
            "get_capabilities()".to_string(),
            nix::errno::from_i32(nix::errno::errno()),
        ))
    } else {
        Ok((hdrp, datap))
    }
}

/// Return the current memlock limit.
pub fn get_memlock_limit() -> Result<usize, OxidebpfError> {
    // use getrlimit() syscall
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        let ret = libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim as *mut _);
        if ret < 0 {
            info!(
                LOGGER.0,
                "get_memlock_limit(); could not get memlock limit, errno: {}",
                nix::errno::errno()
            );
            return Err(OxidebpfError::LinuxError(
                "get_memlock_limit".to_string(),
                nix::errno::Errno::from_i32(nix::errno::errno()),
            ));
        }

        Ok(rlim.rlim_cur as usize)
    }
}

#[cfg(test)]
mod program_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_program_group() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new();

        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["do_mount"]).syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
                || unreachable!(),
            )
            .expect("Could not load programs");
    }

    #[test]
    fn test_memlock_limit() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new().mem_limit(1234567);

        let original_limit = get_memlock_limit().expect("could not get original limit");
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["do_mount"]).syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
                || unreachable!(),
            )
            .expect("Could not load programs");

        let current_limit = get_memlock_limit().expect("could not get current limit");

        assert_eq!(current_limit, 1234567);
        assert_ne!(current_limit, original_limit);

        set_memlock_limit(original_limit).expect("could not revert limit");
    }

    #[test]
    fn test_program_group_array_maps() {
        // Build the path to the test bpf program
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));

        // Create a blueprint from the test bpf program
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");

        // Create a program group that will try and attach the test program to hook points in the kernel
        let mut program_group = ProgramGroup::new();

        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["sys_open", "sys_write"])
                        .syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
                || unreachable!(), // the test will fail if it tries to load a perfmap
            )
            .expect("Could not load programs");

        // Get a particular array map and try and read a value from it
        match program_group.get_array_maps() {
            Some(hash_map) => {
                let array_map = match hash_map.get("__test_map") {
                    Some(map) => map,
                    None => {
                        panic!("There should have been a map with that name")
                    }
                };
                // Get the bpf program to update the map
                std::fs::write("/tmp/baz", "some data").expect("Unable to write file");
                let val: u32 = unsafe { array_map.read(0).expect("Failed to read from map") };
                assert_eq!(val, 1234);

                // Show that we can read and write from the map from user space
                let _ = unsafe {
                    array_map
                        .write(0, 0xAAAAAAAAu32)
                        .expect("Failed to write from map")
                };
                let val: u32 = unsafe { array_map.read(0).expect("Failed to read from map") };
                assert_eq!(val, 0xAAAAAAAA);
            }
            None => {
                panic!("Failed to get maps when they should have been present");
            }
        };
    }

    #[test]
    fn test_program_group_tail_call() {
        // Build the path to the test bpf program
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));

        // Create a blueprint from the test bpf program
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");

        // Create a program group that will try and attach the test program to hook points in the kernel
        let mut program_group = ProgramGroup::new();

        // Load the bpf program
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_tailcall", &["sys_open", "sys_write"]).syscall(true),
                    Program::new("test_program_tailcall_update_map", &[])
                        .tail_call_map_index("__test_tailcall_map", 0),
                ])],
                || unreachable!(),
            )
            .expect("Could not load programs");

        // Get a particular array map and try and read a value from it
        match program_group.get_array_maps() {
            Some(hash_map) => {
                let array_map = match hash_map.get("__test_map") {
                    Some(map) => map,
                    None => {
                        panic!("There should have been a map with that name")
                    }
                };
                // Get the bpf program to update the map
                std::fs::write("/tmp/bar", "some data").expect("Unable to write file");

                // the tail-called program should set this value
                let val: u32 = unsafe { array_map.read(150).expect("Failed to read from map") };
                assert_eq!(val, 111);
            }
            None => {
                panic!("Failed to get maps when they should have been present");
            }
        };
    }

    #[test]
    fn test_program_group_hash_maps() {
        // Build the path to the test bpf program
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));

        // Create a blueprint from the test bpf program
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");

        // Create a program group that will try and attach the test program to hook points in the kernel
        let mut program_group = ProgramGroup::new();

        // Load the bpf program
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["sys_open", "sys_write"])
                        .syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
                || unreachable!(), // the test will fail if it tries to load a perfmap
            )
            .expect("Could not load programs");

        // Get a particular array map and try and read a value from it
        match program_group.get_hash_maps() {
            Some(map) => {
                let hash_map = match map.get("__test_hash_map") {
                    Some(m) => m,
                    None => {
                        panic!("There should have been a map with that name")
                    }
                };
                // Get the bpf program to update the map
                std::fs::write("/tmp/foo", "some data").expect("Unable to write file");
                let val: u64 =
                    unsafe { hash_map.read(0x12345u64).expect("Failed to read from map") };
                assert_eq!(val, 1234);

                // Show that we can read and write from the map from user space
                let _ = unsafe {
                    hash_map
                        .write(std::process::id() as u64, 0xAAAAAAAAu64)
                        .expect("Failed to write from map")
                };
                let val: u64 = unsafe {
                    hash_map
                        .read(std::process::id() as u64)
                        .expect("Failed to read from map")
                };
                assert_eq!(val, 0xAAAAAAAA);
            }
            None => {
                panic!("Failed to get maps when they should have been present");
            }
        };
    }
}

#[cfg(test)]
mod scheduling_tests {
    use thread_priority::ThreadPriority;

    use super::*;

    #[test]
    fn idle_no_priority() {
        let policy = SchedulingPolicy::Idle;
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Crossplatform(0_u8.try_into().unwrap());

        assert_eq!(converted, expected);
    }

    #[test]
    fn other_no_priority() {
        let policy = SchedulingPolicy::Other(10);
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Crossplatform(0_u8.try_into().unwrap());

        assert_eq!(converted, expected);
    }

    #[test]
    fn batch_no_priority() {
        let policy = SchedulingPolicy::Batch(39);
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Crossplatform(0_u8.try_into().unwrap());

        assert_eq!(converted, expected);
    }

    #[test]
    fn fifo_clamped_priority() {
        let policy = SchedulingPolicy::FIFO(0);
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Crossplatform(1_u8.try_into().unwrap());

        assert_eq!(converted, expected);
    }

    #[test]
    fn sched_clamped_priority() {
        let policy = SchedulingPolicy::RR(100);
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Crossplatform(99_u8.try_into().unwrap());

        assert_eq!(converted, expected);
    }

    #[test]
    fn deadline_priority() {
        let policy = SchedulingPolicy::Deadline(1, 2, 3);
        let converted: ThreadPriority = policy.into();
        let expected = ThreadPriority::Deadline(1, 2, 3);

        assert_eq!(converted, expected);
    }
}

/// An enum of the different BPF program types.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum ProgramType {
    /// Unspecified program type.
    Unspec,
    /// A kprobe that can be attached at the function (or syscall) start or offset.
    Kprobe,
    /// A kprobe that can be attached at the return of a function (or syscall).
    Kretprobe,
    /// A uprobe that can be attached to a function in a program or pid at the start or offset.
    Uprobe,
    /// A uprobe that can be attached to the return of a function in a program or pid.
    Uretprobe,
    /// Stable (in theory) kernel static instrumentation points.
    Tracepoint,
    /// A tracepoint with raw arguments accessible, without `TP_fast_assign()` applied.
    RawTracepoint,
}

impl Default for ProgramType {
    fn default() -> Self {
        ProgramType::Unspec
    }
}

impl From<&str> for ProgramType {
    fn from(value: &str) -> ProgramType {
        match value {
            "kprobe" => ProgramType::Kprobe,
            "kretprobe" => ProgramType::Kretprobe,
            "uprobe" => ProgramType::Uprobe,
            "uretprobe" => ProgramType::Uretprobe,
            "tracepoint" => ProgramType::Tracepoint,
            "rawtracepoint" => ProgramType::RawTracepoint,
            _ => ProgramType::Unspec,
        }
    }
}

impl Display for ProgramType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ProgramType::Unspec => "unspec",
                ProgramType::Kprobe => "kprobe",
                ProgramType::Kretprobe => "kretprobe",
                ProgramType::Uprobe => "uprobe",
                ProgramType::Uretprobe => "uretprobe",
                ProgramType::Tracepoint => "tracepoint",
                ProgramType::RawTracepoint => "rawtracepoint",
            }
        )
    }
}
