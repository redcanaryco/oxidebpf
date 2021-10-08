//! A fully MIT licensed library for managing eBPF programs.
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
mod error;
mod maps;
mod perf;

pub use blueprint::{ProgramBlueprint, SectionType};
pub use error::OxidebpfError;
pub use maps::{ArrayMap, BpfHashMap, RWMap};

use blueprint::ProgramObject;
use bpf::{
    constant::bpf_map_type,
    syscall::{self, bpf_map_update_elem},
    BpfAttr, MapConfig, SizedBpfAttr,
};

use maps::{PerCpu, PerfEvent, PerfMap, ProgMap};
use perf::{
    constant::{perf_event_sample_format, perf_sw_ids, perf_type_id},
    syscall::{attach_kprobe, attach_kprobe_debugfs, attach_uprobe, attach_uprobe_debugfs},
    PerfEventAttr, PerfSample, PerfWakeup,
};

use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
    format,
    io::{BufRead, BufReader, BufWriter, Write},
    os::unix::io::RawFd,
    thread,
    time::Duration,
};

use crossbeam_channel::{bounded, Receiver, Sender};
use lazy_static::lazy_static;
use libc::{c_int, pid_t};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use nix::errno::Errno;
use slog::{crit, info, o, warn, Drain, Logger};
use slog_atomic::{AtomicSwitch, AtomicSwitchCtrl};

lazy_static! {
    pub static ref LOGGER: (Logger, AtomicSwitchCtrl) = create_slogger_root();
}

fn create_slogger_root() -> (slog::Logger, AtomicSwitchCtrl) {
    let drain = slog::Logger::root(slog::Discard, o!());
    let drain = slog_async::Async::new(drain).build().fuse();
    let drain = AtomicSwitch::new(drain);
    (slog::Logger::root(drain.clone(), o!()), drain.ctrl())
}

#[cfg(target_arch = "aarch64")]
const ARCH_SYSCALL_PREFIX: &str = "__arm64_";
#[cfg(target_arch = "x86_64")]
const ARCH_SYSCALL_PREFIX: &str = "__x64_";

/// Message format for messages sent back across the channel. It includes
/// the map name, cpu id, and message data.
#[derive(Debug)]
pub struct PerfChannelMessage(
    /// The name of the map this message is from.
    pub String,
    /// The cpuid of the CPU this message is from.
    pub i32,
    /// The data in the message.
    pub Vec<u8>,
);

#[derive(Clone)]
struct Channel {
    tx: Sender<PerfChannelMessage>,
    rx: Receiver<PerfChannelMessage>,
}

/// A group of eBPF [`ProgramVersion`](struct@ProgramVersion)s that a user
/// wishes to load from a blueprint. The loader will attempt each `ProgramVersion`
/// in order until one successfully loads, or none do.
pub struct ProgramGroup<'a> {
    event_buffer_size: usize,
    channel: Channel,
    loaded_version: Option<ProgramVersion<'a>>,
    loaded: bool,
}

/// A group of eBPF [`Program`](struct@Program)s that a user wishes to load.
#[derive(Default)]
pub struct ProgramVersion<'a> {
    programs: Vec<Program<'a>>,
    fds: HashSet<RawFd>,
    ev_names: HashSet<String>,
    array_maps: HashMap<String, ArrayMap>,
    hash_maps: HashMap<String, BpfHashMap>,
    has_perf_maps: bool,
    mem_limit: Option<usize>,
    original_limit: usize,
    polling_delay: u64,
}

impl<'a> Clone for ProgramVersion<'a> {
    fn clone(&self) -> Self {
        Self {
            programs: self.programs.clone(),
            ev_names: self.ev_names.clone(),
            array_maps: self.array_maps.clone(),
            hash_maps: self.hash_maps.clone(),
            has_perf_maps: self.has_perf_maps,
            mem_limit: self.mem_limit,
            original_limit: self.original_limit,
            fds: self
                .fds
                .iter()
                .map(|fd| unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 3) })
                .collect(),
            polling_delay: self.polling_delay,
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
                                        "multiple kprobe load errors: {:?}; {:?}", e, s
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

        maps::get_cpus()?
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
                                        "multiple uprobe load errors: {:?}; {:?}", e, s
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
                    info!(LOGGER.0, "attach error: {:?}", e);
                    Err(e)
                }
            }
        }
    }

    fn attach_probes(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        if !self.loaded {
            info!(
                LOGGER.0,
                "attempting to attach probes while program not loaded"
            );
            return Err(OxidebpfError::ProgramNotLoaded);
        }

        match &self.kind {
            Some(ProgramType::Kprobe | ProgramType::Kretprobe) => self.attach_kprobe(),
            Some(ProgramType::Uprobe | ProgramType::Uretprobe) => self.attach_uprobe(),
            Some(t) => {
                info!(
                    LOGGER.0,
                    "attempting to load unsupported program type {:?}", t
                );
                Err(OxidebpfError::UnsupportedProgramType)
            }
            _ => {
                info!(
                    LOGGER.0,
                    "attempting to load unsupported program type: unknown"
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

impl<'a> ProgramGroup<'a> {
    /// Create a program group that will manage multiple [`ProgramVersion`](struct@ProgramVersion)s.
    ///
    /// This creates a bounded channel of the given (optional) size for receiving messages
    /// from any perfmaps that may be loaded by `Program`s in given `ProgramVersion`.
    /// Together with [`load()`](fn.load.html), this is the primary public interface of the
    /// oxidebpf library. You feed your `ProgramGroup` a collection of `ProgramVersion`s,
    /// each with their own set of `Program`s. Note that you must provide your `ProgramGroup`
    /// with a [`ProgramBlueprint`](struct@ProgramBlueprint). The blueprint contains the parsed
    /// object file with all the eBPF programs and maps you may load.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::ProgramBlueprint;
    /// use oxidebpf::{ProgramGroup, Program, ProgramVersion, ProgramType};
    /// use std::path::PathBuf;
    ///
    /// let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    ///             .join("test")
    ///             .join(format!("test_program_{}", std::env::consts::ARCH));
    /// let program_blueprint =
    ///     ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
    ///         .expect("Could not open test object file");
    ///
    /// ProgramGroup::new(None);
    /// ```
    pub fn new(event_buffer_size: Option<usize>) -> ProgramGroup<'a> {
        // grab all the telemetry
        let aa_status = std::process::Command::new("aa-status").output();
        info!(LOGGER.0, "aa-status: {:?}", aa_status);
        let se_export = std::process::Command::new("semanage")
            .args(["export", "-f", "/dev/stdout"])
            .output();

        info!(LOGGER.0, "semanage export: {:?}", se_export);
        let event_buffer_size = event_buffer_size.unwrap_or(1024);
        let (tx, rx): (Sender<PerfChannelMessage>, Receiver<PerfChannelMessage>) =
            bounded(event_buffer_size);
        let channel = Channel { tx, rx };
        ProgramGroup {
            event_buffer_size,
            channel,
            loaded_version: None,
            loaded: false,
        }
    }

    /// Attempt to load [`ProgramVersion`](struct@ProgramVersion)s until one
    /// successfully loads.
    ///
    /// This function attempts to load each `ProgramVersion` in the order given until
    /// one successfully loads. When one loads, if that version had a perfmap channel,
    /// a [`PerfChannelMessage`](struct@PerfChannelMessage) receiver crossbeam channel
    /// is available after loading by calling `get_receiver()` on the `ProgramGroup`.
    /// If none load, a `NoProgramVersionLoaded` error is returned, along with all the
    /// internal errors generated during attempted loading.
    ///
    /// NOTE: Once you call `load()`, it cannot be called again without re-creating
    /// the `ProgramGroup`.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::ProgramBlueprint;
    /// use oxidebpf::{ProgramGroup, Program, ProgramVersion, ProgramType};
    /// use std::path::PathBuf;
    ///
    /// let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    ///             .join("test")
    ///             .join(format!("test_program_{}", std::env::consts::ARCH));
    /// let program_blueprint =
    ///     ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
    ///         .expect("Could not open test object file");
    /// let mut program_group = ProgramGroup::new(
    ///     None,
    /// );
    ///
    /// program_group.load(
    ///     program_blueprint,
    ///     vec![ProgramVersion::new(vec![Program::new(
    ///         "test_program",
    ///         &["do_mount"],
    ///     ).syscall(true)])],
    /// ).expect("Could not load programs");
    /// ```
    pub fn load(
        &mut self,
        program_blueprint: ProgramBlueprint,
        program_versions: Vec<ProgramVersion<'a>>,
    ) -> Result<(), OxidebpfError> {
        if self.loaded {
            info!(
                LOGGER.0,
                "error: attempting to load a program group that was already loaded"
            );
            return Err(OxidebpfError::ProgramGroupAlreadyLoaded);
        }
        let mut errors = vec![];
        for mut program_version in program_versions {
            match program_version.load_program_version(
                program_blueprint.clone(),
                self.channel.clone(),
                self.event_buffer_size,
            ) {
                Ok(()) => {
                    self.loaded_version = Some(program_version);
                    break;
                }
                Err(e) => {
                    errors.push(e);
                    set_memlock_limit(program_version.original_limit)?;
                }
            };
        }

        match &self.loaded_version {
            None => {
                info!(
                    LOGGER.0,
                    "error: no program version was able to load for {:?}, errors: {:?}",
                    match std::env::current_exe() {
                        Ok(p) => p,
                        Err(_) => std::path::PathBuf::from("unknown"),
                    },
                    errors
                );
                // send up system logs
                let journalctl = std::process::Command::new("journalctl")
                    .args(["--no-pager"])
                    .output();
                info!(LOGGER.0, "journalctl log: {:?}", journalctl);
                let kern_log = std::process::Command::new("cat")
                    .args(["/var/log/kern.log"])
                    .output();
                info!(LOGGER.0, "kern.log: {:?}", kern_log);
                let audit_log = std::process::Command::new("cat")
                    .args(["/var/log/audit.log"])
                    .output();
                info!(LOGGER.0, "autdit.log: {:?}", audit_log);
                let syslog = std::process::Command::new("cat")
                    .args(["/var/log/syslog"])
                    .output();
                info!(LOGGER.0, "syslog: {:?}", syslog);
                Err(OxidebpfError::NoProgramVersionLoaded(errors))
            }
            Some(_) => {
                self.loaded = true;
                Ok(())
            }
        }
    }

    /// Returns the receiver channel for this `ProgramGroup`, if it exists.
    ///
    /// This will become available when perfmaps are successfully loaded by any
    /// `ProgramVersion`.
    pub fn get_receiver(&self) -> Option<Receiver<PerfChannelMessage>> {
        match &self.loaded_version {
            None => None,
            Some(lv) => {
                if lv.has_perf_maps {
                    Some(self.channel.clone().rx)
                } else {
                    None
                }
            }
        }
    }

    /// Get a reference to the array maps in the [`Program`](struct@ProgramGroup)s.
    pub fn get_array_maps(&self) -> Option<&HashMap<String, ArrayMap>> {
        self.loaded_version.as_ref().map(|ver| &ver.array_maps)
    }

    /// Get a reference to the hash maps in the ['Program'](struct@ProgramGroup)s.
    pub fn get_hash_maps(&self) -> Option<&HashMap<String, BpfHashMap>> {
        self.loaded_version.as_ref().map(|ver| &ver.hash_maps)
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
                "unable to set memlock limit, errno: {}",
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

fn get_memlock_limit() -> Result<usize, OxidebpfError> {
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
                "could not get memlock limit, errno: {}",
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

impl ProgramVersion<'_> {
    /// Create a new `ProgramVersion` from a vector of [`Program`](struct@Program)s.
    ///
    /// The newly created `ProgramVersion` should be given to a
    /// [`ProgramGroup`](struct@ProgramGroup) for loading. The `ProgramVersion` encapsulates
    /// all the logic for loading, attaching, and returning events from a single clustering
    /// of eBPF [`Program`](struct@Program)s. Each `ProgramVersion` should be intended to act
    /// as an independent unit, in the absence of other `ProgramVersion`s.
    ///
    /// # Panics
    ///
    /// *  When dropping a `ProgramVersion` that uses debugfs, if the drop routine cannot
    /// reach the correct files in debugfs it will panic.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::{ProgramVersion, Program, ProgramType};
    ///
    /// let program_vec = vec![
    ///     Program::new(
    ///         "sys_ptrace_write",
    ///         &["sys_ptrace"],
    ///     ).syscall(true),
    ///     Program::new(
    ///         "sys_process_vm_writev",
    ///         &["sys_process_vm_writev"],
    ///     ).syscall(true)
    /// ];
    ///
    /// ProgramVersion::new(program_vec);
    /// ```
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::new(),
            ev_names: HashSet::new(),
            array_maps: HashMap::new(),
            hash_maps: HashMap::new(),
            has_perf_maps: false,
            mem_limit: None,
            original_limit: get_memlock_limit().unwrap_or(libc::RLIM_INFINITY as usize),
            polling_delay: 100,
        }
    }

    /// Manually set the memlock ulimit for this `ProgramVersion`.
    pub fn mem_limit(mut self, limit: usize) -> Self {
        self.mem_limit = Some(limit);
        self
    }

    /// Manually specify the perfmap polling interval for this `ProgramVersion`.
    pub fn polling_delay(mut self, delay: u64) -> Self {
        self.polling_delay = delay;
        self
    }

    fn event_poller(
        &self,
        perfmaps: Vec<PerfMap>,
        tx: Sender<PerfChannelMessage>,
    ) -> Result<(), OxidebpfError> {
        let polling_delay = Duration::from_millis(self.polling_delay);

        let result = std::thread::Builder::new()
            .name("PerfMapPoller".to_string())
            .spawn(move || perf_map_poller(perfmaps, tx, polling_delay));

        match result {
            Ok(_) => Ok(()),
            Err(e) => {
                crit!(LOGGER.0, "error in thread polling: {:?}", e);
                Err(OxidebpfError::ThreadPollingError)
            }
        }
    }

    fn load_program_version(
        &mut self,
        mut program_blueprint: ProgramBlueprint,
        channel: Channel,
        event_buffer_size: usize,
    ) -> Result<(), OxidebpfError> {
        let mut matching_blueprints: Vec<ProgramObject> = self
            .programs
            .iter()
            .map(|p| {
                program_blueprint
                    .programs
                    .get(p.name)
                    .cloned()
                    .ok_or(OxidebpfError::ProgramNotFound)
            })
            .collect::<Result<_, OxidebpfError>>()?;

        let mut perfmaps = vec![];
        // load maps and save fds and apply relocations
        let mut loaded_maps = HashSet::new();
        let mut tailcall_tables = HashMap::new();

        match self.mem_limit {
            // check if user set a memlock limit, if so apply it
            Some(limit) => set_memlock_limit(limit)?,
            // if not, move on...
            None => {
                // iterate over all the program objects and pull out the required maps
                let mut sum = 0;
                // look at the required maps and sum how much memory they'll need
                for program_object in matching_blueprints.iter_mut() {
                    for name in program_object.required_maps().iter() {
                        let map = program_blueprint.maps.get_mut(name).ok_or_else(|| {
                            info!(
                                LOGGER.0,
                                "map not found while calculating mem limit: {}",
                                name.to_string()
                            );
                            OxidebpfError::MapNotFound(name.to_string())
                        })?;
                        sum += ((map.definition.key_size + map.definition.value_size)
                            * map.definition.max_entries) as usize;
                    }
                    sum += program_object.code.0.len() * 8; // BPF insns are always 8 bytes
                }
                // tmp override, set memlock to unlimited unconditionally
                set_memlock_limit(libc::RLIM_INFINITY as usize)?;
                //// check memlock limit
                //let current_limit = get_memlock_limit()?;
                //if sum > current_limit {
                //    set_memlock_limit(sum)?;
                //}
                //// if we're under, do nothing
            }
        }

        for program_object in matching_blueprints.iter_mut() {
            for name in program_object.required_maps().iter() {
                let map = program_blueprint
                    .maps
                    .get_mut(name)
                    .ok_or_else(|| {
                        info!(LOGGER.0, "map not found while iterating through required maps, map name: {}; program name: {}", name, program_object.name);
                        OxidebpfError::MapNotFound(name.to_string())
                    })?;

                if !loaded_maps.contains(&map.name) {
                    let sized_attr = SizedBpfAttr {
                        bpf_attr: BpfAttr {
                            map_config: MapConfig::from(map.definition),
                        },
                        size: 20,
                    };
                    match map.definition.map_type {
                        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                            let fd =
                                unsafe { syscall::bpf_map_create_with_sized_attr(sized_attr)? };
                            self.fds.insert(fd);
                            map.set_loaded(fd);
                            program_object.fixup_map_relocation(fd, map)?;

                            let event_attr = PerfEventAttr {
                                config: perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as u64,
                                size: std::mem::size_of::<PerfEventAttr>() as u32,
                                p_type: perf_type_id::PERF_TYPE_SOFTWARE,
                                sample_type: perf_event_sample_format::PERF_SAMPLE_RAW as u64,
                                sample_union: PerfSample { sample_period: 1 },
                                wakeup_union: PerfWakeup { wakeup_events: 1 },
                                ..Default::default()
                            };
                            let perfmap =
                                PerfMap::new_group(&map.name, event_attr, event_buffer_size)?;

                            perfmap
                                .iter()
                                .try_for_each(|p| -> Result<(), OxidebpfError> {
                                    self.fds.insert(unsafe {
                                        libc::fcntl(p.ev_fd as RawFd, libc::F_DUPFD_CLOEXEC, 3)
                                    });
                                    bpf_map_update_elem::<i32, i32>(fd, p.cpuid(), p.ev_fd as i32)
                                })?;

                            perfmaps.extend(perfmap);
                        }
                        bpf_map_type::BPF_MAP_TYPE_ARRAY => {
                            // Create the new array Map
                            unsafe {
                                match ArrayMap::new(
                                    name,
                                    map.definition.value_size as u32,
                                    map.definition.max_entries,
                                ) {
                                    Ok(new_map) => {
                                        let fd = libc::fcntl(
                                            *new_map.get_fd(),
                                            libc::F_DUPFD_CLOEXEC,
                                            3,
                                        );
                                        self.fds.insert(fd);
                                        map.set_loaded(fd);
                                        program_object.fixup_map_relocation(fd, map)?;
                                        self.array_maps.insert(name.to_string(), new_map);
                                    }
                                    Err(err) => return Err(err),
                                };
                            }
                        }
                        bpf_map_type::BPF_MAP_TYPE_HASH => unsafe {
                            match BpfHashMap::new(
                                name,
                                map.definition.key_size as u32,
                                map.definition.value_size as u32,
                                map.definition.max_entries,
                            ) {
                                Ok(new_map) => {
                                    let fd =
                                        libc::fcntl(*new_map.get_fd(), libc::F_DUPFD_CLOEXEC, 3);
                                    self.fds.insert(fd);
                                    map.set_loaded(fd);
                                    program_object.fixup_map_relocation(fd, map)?;
                                    self.hash_maps.insert(name.to_string(), new_map);
                                }
                                Err(err) => return Err(err),
                            };
                        },
                        bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY => {
                            match ProgMap::new(name, map.definition.max_entries) {
                                Ok(new_map) => {
                                    let fd = unsafe {
                                        libc::fcntl(*new_map.get_fd(), libc::F_DUPFD_CLOEXEC, 3)
                                    };
                                    self.fds.insert(fd);
                                    map.set_loaded(fd);
                                    program_object.fixup_map_relocation(fd, map)?;
                                    tailcall_tables.insert(new_map.base.name.to_string(), new_map);
                                }
                                Err(err) => return Err(err),
                            };
                        }
                        _ => {
                            let fd =
                                unsafe { syscall::bpf_map_create_with_sized_attr(sized_attr)? };
                            self.fds.insert(fd);
                            map.set_loaded(fd);
                            program_object.fixup_map_relocation(fd, map)?;
                        }
                    }
                    loaded_maps.insert(map.name.to_string());
                } else {
                    program_object.fixup_map_relocation(map.get_fd()?, map)?;
                }
            }
        }

        // load and attach programs
        for blueprint in matching_blueprints.into_iter() {
            // Programs are kept separate from ProgramBlueprints to allow users to specify
            // different blueprints/files for the same set of programs, should they choose.
            // This means we need to do ugly filters like this
            let name = blueprint.name;
            let programs: Vec<&mut Program> = self
                .programs
                .iter_mut()
                .filter(|p| p.name == name)
                .collect();

            for p in programs {
                // check if the user specified a kind, otherwise set it based on the blueprint
                let program_type = match &p.kind {
                    Some(k) => k,
                    None => {
                        p.kind = Some(blueprint.program_type);
                        &blueprint.program_type
                    }
                };
                let fd = match syscall::bpf_prog_load(
                    u32::from(program_type),
                    &blueprint.code,
                    blueprint.license.clone(),
                    blueprint.kernel_version,
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        // if this program is optional, go to the next one
                        if p.optional {
                            continue;
                        }

                        // If it's not optional, fail out of the whole Version
                        info!(LOGGER.0, "failed out of version with error {:?}", e);
                        return Err(e);
                    }
                };

                // fix up any tail call mapping that might exist
                if let Some(tcm) = &p.tail_call_mapping {
                    match tailcall_tables.get(&tcm.map) {
                        Some(map) => bpf_map_update_elem(*map.get_fd(), tcm.index, fd)?,
                        None => {
                            info!(
                                LOGGER.0,
                                "tail call mapping not found, could not update: {:?}",
                                tcm.map.clone()
                            );
                            return Err(OxidebpfError::MapNotFound(tcm.map.clone()));
                        }
                    }
                }

                // SAFETY: Program object `p` takes the `fd` here, but does NOT manage its lifetime
                p.loaded_as(fd);
                match p.attach() {
                    Err(e) => {
                        if !p.optional {
                            info!(
                                LOGGER.0,
                                "failed mandatory program load: {}; error: {:?}", p.name, e
                            );
                            return Err(e);
                        }
                    }
                    Ok(s) => {
                        self.ev_names.extend(s.0);
                        // SAFETY: these fds that came from `p.attach()` are not managed by `p`
                        self.fds.extend(s.1);
                    }
                }
                self.fds.insert(fd);
            }
        }

        // start event poller and pass back channel, if one exists
        if !perfmaps.is_empty() {
            self.has_perf_maps = true;
            self.event_poller(perfmaps, channel.tx)?;
        }
        Ok(())
    }
}

impl<'a> Drop for ProgramVersion<'a> {
    fn drop(&mut self) {
        // Detach everything, close remaining attachpoints
        // SAFETY: these fds must be wholly owned by `ProgramVersion`.
        for fd in self.fds.iter() {
            unsafe {
                libc::close(*fd as c_int);
            }
        }

        // We are intentionally enumerating and closing _all_ debugfs created
        // probes here, on the off chance that one gets missed somehow. Otherwise,
        // we might end up stuck with a bunch of unused probes clogging the namespace.
        // If it has oxidebpf_ it's probably one of ours. This avoids conflicting
        // with customer user probes or probes from other frameworks.

        // uprobe
        let up_file = match std::fs::OpenOptions::new()
            .append(true)
            .write(true)
            .read(true)
            .open("/sys/kernel/debug/tracing/uprobe_events")
        {
            Ok(f) => f,
            Err(e) => {
                warn!(LOGGER.0, "could not close uprobes: {:?}", e);
                return;
            }
        };
        let up_reader = BufReader::new(&up_file);
        let mut up_writer = BufWriter::new(&up_file);
        for line in up_reader.lines() {
            let line = line.unwrap();
            if line.contains("oxidebpf_") {
                if let Err(e) = up_writer.write_all(format!("-:{}\n", &line[2..]).as_bytes()) {
                    warn!(LOGGER.0, "could not close uprobe [{}]: {:?}", line, e);
                    return;
                }
            }
        }
        // kprobe
        let kp_file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open("/sys/kernel/debug/tracing/kprobe_events")
        {
            Ok(f) => f,
            Err(e) => {
                warn!(LOGGER.0, "could not close kprobes: {:?}", e);
                return;
            }
        };
        let kp_reader = BufReader::new(&kp_file);
        let mut kp_writer = BufWriter::new(&kp_file);
        for line in kp_reader.lines() {
            let line = line.unwrap();
            if line.contains("oxidebpf_") {
                if let Err(e) = kp_writer.write_all(format!("-:{}\n", &line[2..]).as_bytes()) {
                    warn!(LOGGER.0, "could not close kprobe [{}]: {:?}", line, e);
                    return;
                }
            }
        }
    }
}

fn perf_map_poller(
    perfmaps: Vec<PerfMap>,
    tx: Sender<PerfChannelMessage>,
    polling_delay: Duration,
) {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            crit!(LOGGER.0, "error creating poller: {:?}", e);
            return;
        }
    };

    let mut tokens: HashMap<Token, PerfMap> = HashMap::new();
    for p in perfmaps {
        let token = Token(p.ev_fd as usize);

        if let Err(e) = poll
            .registry()
            .register(&mut SourceFd(&p.ev_fd), token, Interest::READABLE)
        {
            crit!(LOGGER.0, "error registering poller: {:?}", e);
            return;
        }

        tokens.insert(token, p);
    }

    let mut events = Events::with_capacity(1024);

    // for tracking dropped event statistics inside the loop
    let mut dropped = 0;
    let mut processed = 0;

    'outer: loop {
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {}
            Err(e) => match nix::errno::Errno::from_i32(nix::errno::errno()) {
                Errno::EINTR => continue,
                _ => {
                    crit!(LOGGER.0, "unrecoverable polling error: {:?}", e);
                    return;
                }
            },
        }
        let mut perf_events: Vec<(String, i32, Option<PerfEvent>)> = Vec::new();
        events
            .iter()
            .filter(|event| event.is_readable())
            .filter_map(|e| tokens.get(&e.token()))
            .for_each(|perfmap| loop {
                match perfmap.read() {
                    Ok(perf_event) => {
                        perf_events.push((
                            perfmap.name.to_string(),
                            perfmap.cpuid() as i32,
                            perf_event,
                        ));
                    }
                    Err(OxidebpfError::NoPerfData) => {
                        // we're done reading
                        return;
                    }
                    Err(e) => {
                        crit!(LOGGER.0, "perfmap read error: {:?}", e);
                        return;
                    }
                }
            });
        for event in perf_events.into_iter() {
            let message = match event.2 {
                None => continue,
                Some(PerfEvent::Lost(_)) => {
                    dropped += 1;
                    if (dropped >= 1000 || processed >= 10000) && dropped > 0 {
                        let d = dropped;
                        dropped = 0;
                        processed = 0;
                        PerfChannelMessage("DROPPED".to_owned(), d, vec![])
                    } else {
                        continue;
                    }
                }
                Some(PerfEvent::Sample(e)) => PerfChannelMessage(event.0, event.1, e.data),
            };
            match tx.send(message) {
                Ok(_) => {}
                Err(_) => break 'outer,
            };

            processed += 1;
        }
        thread::sleep(polling_delay);
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
        let mut program_group = ProgramGroup::new(None);

        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["do_mount"]).syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
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
        let mut program_group = ProgramGroup::new(None);

        let original_limit = get_memlock_limit().expect("could not get original limit");
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["do_mount"]).syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])
                .mem_limit(1234567)],
            )
            .expect("Could not load programs");

        let current_limit = get_memlock_limit().expect("could not get current limit");

        assert_eq!(current_limit, 1234567);
        assert_ne!(current_limit, original_limit);

        set_memlock_limit(original_limit).expect("could not revert limit");
    }

    #[test]
    fn test_memlock_limit_reverts() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new(None);

        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![Program::new(
                    "test_program_map_update",
                    &["__not_a_real_syscall_expect_failure"],
                )
                .syscall(true)])
                .mem_limit(1234567)],
            )
            .expect_err("program_group was able to load");

        let current_limit = get_memlock_limit().expect("could not get current limit");

        assert_ne!(current_limit, 1234567);
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
        let mut program_group = ProgramGroup::new(None);

        // Load the bpf program
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["sys_open", "sys_write"])
                        .syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
            )
            .expect("Could not load programs");
        let rx = program_group.get_receiver();
        assert!(rx.is_none());

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
        let mut program_group = ProgramGroup::new(None);

        // Load the bpf program
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_tailcall", &["sys_open", "sys_write"]).syscall(true),
                    Program::new("test_program_tailcall_update_map", &[])
                        .tail_call_map_index("__test_tailcall_map", 0),
                ])],
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
        let mut program_group = ProgramGroup::new(None);

        // Load the bpf program
        program_group
            .load(
                program_blueprint,
                vec![ProgramVersion::new(vec![
                    Program::new("test_program_map_update", &["sys_open", "sys_write"])
                        .syscall(true),
                    Program::new("test_program", &["do_mount"]).syscall(true),
                ])],
            )
            .expect("Could not load programs");
        let rx = program_group.get_receiver();
        assert!(rx.is_none());

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
