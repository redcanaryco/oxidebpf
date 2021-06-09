//! A fully MIT licensed library for managing eBPF programs.
//!
//! `oxidebpf` allows a user to easily manage a pre-built eBPF object file, creating
//! groups of programs based on functionality and loading them as units.
//! For a quick getting-started, see the documentation for [`ProgramGroup`](struct@ProgramGroup)'s
//! `new()` and `load()` functions.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::io::RawFd;

use crossbeam_channel::{bounded, Receiver, Sender};
use libc::{c_int, pid_t};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use perf::syscall::{attach_kprobe, attach_uprobe};
use perf::{PerfEventAttr, PerfSample, PerfWakeup};

use crate::blueprint::{ProgramBlueprint, ProgramObject};
use crate::bpf::constant::bpf_map_type;
use crate::bpf::syscall::bpf_map_update_elem;
use crate::bpf::{syscall, BpfAttr, MapConfig, SizedBpfAttr};
use crate::error::OxidebpfError;
use crate::maps::PerfEvent;
use crate::maps::{PerCpu, PerfMap};
use crate::perf::constant::{perf_event_sample_format, perf_sw_ids, perf_type_id};
use crate::perf::syscall::{attach_kprobe_debugfs, attach_uprobe_debugfs};
use nix::errno::Errno;
use std::time::Duration;

pub mod blueprint;
mod bpf;
mod error;
mod maps;
mod perf;

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
    program_blueprint: ProgramBlueprint,
    program_versions: Vec<ProgramVersion<'a>>,
    event_buffer_size: usize,
    channel: Channel,
}

/// A group of eBPF [`Program`](struct@Program)s that a user wishes to load.
pub struct ProgramVersion<'a> {
    programs: Vec<Program<'a>>,
    fds: HashSet<RawFd>,
    ev_names: HashSet<String>,
}

/// The description of an individual eBPF program. Note: This is _not_ the same
/// as the eBPF program itself, the actual binary is loaded from a
/// [`ProgramBlueprint`](struct@ProgramBlueprint).
pub struct Program<'a> {
    kind: ProgramType,
    name: &'a str,
    attach_points: Vec<String>,
    optional: bool,
    loaded: bool,
    is_syscall: bool,
    fd: RawFd,
    pid: Option<pid_t>,
}

impl<'a> Program<'a> {
    /// Create a new program specification.
    ///
    /// You must provide the program type, the name of the program section in your
    /// blueprint's object file (see ['ProgramBlueprint'](struct@ProgramBlueprint))
    /// and a vector of attachment points.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::{Program, ProgramType};
    ///
    /// Program::new(
    ///     ProgramType::Kprobe,
    ///     "sys_ptrace_write",
    ///     vec!["do_mount"],
    /// ).optional(false).syscall(true);
    /// ```
    pub fn new(kind: ProgramType, name: &'a str, attach_points: Vec<&'a str>) -> Program<'a> {
        Self {
            kind,
            name,
            attach_points: attach_points.iter().map(|ap| ap.to_string()).collect(),
            optional: false,
            loaded: false,
            is_syscall: false,
            fd: 0,
            pid: None,
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

    fn attach_kprobe(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        let mut errs = Vec::<OxidebpfError>::new();
        let mut paths = Vec::<String>::new();
        let mut fds = Vec::<RawFd>::new();
        for cpu in crate::maps::get_cpus()?.iter() {
            self.attach_points.iter().for_each(|attach_point| {
                match attach_kprobe(
                    self.fd,
                    attach_point,
                    self.kind == ProgramType::Kretprobe,
                    None,
                    *cpu,
                ) {
                    Ok(fd) => fds.push(fd),
                    Err(e) => {
                        match attach_kprobe_debugfs(
                            self.fd,
                            attach_point,
                            self.kind == ProgramType::Kretprobe,
                            None,
                            *cpu,
                        ) {
                            Ok(s) => paths.push(s),
                            Err(s) => {
                                errs.push(e);
                                errs.push(s);
                            }
                        }
                    }
                }
            });
        }

        if errs.is_empty() {
            Ok((paths, fds))
        } else {
            Err(OxidebpfError::MultipleErrors(errs))
        }
    }

    fn attach_uprobe(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        let mut errs = Vec::<OxidebpfError>::new();
        let mut paths = Vec::<String>::new();
        let mut fds = Vec::<RawFd>::new();
        for cpu in crate::maps::get_cpus()?.iter() {
            self.attach_points.iter().for_each(|attach_point| {
                match attach_uprobe(
                    self.fd,
                    attach_point,
                    self.kind == ProgramType::Uretprobe,
                    None,
                    *cpu,
                    self.pid.unwrap_or(-1),
                ) {
                    Ok(fd) => fds.push(fd),
                    Err(e) => {
                        match attach_uprobe_debugfs(
                            self.fd,
                            attach_point,
                            self.kind == ProgramType::Uretprobe,
                            None,
                            *cpu,
                            self.pid.unwrap_or(-1),
                        ) {
                            Ok(s) => paths.push(s),
                            Err(s) => {
                                errs.push(e);
                                errs.push(s)
                            }
                        }
                    }
                }
            });
        }
        if errs.is_empty() {
            Ok((paths, fds))
        } else {
            Err(OxidebpfError::MultipleErrors(errs))
        }
    }

    fn attach(&mut self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        match self.attach_probes() {
            Ok(res) => Ok(res),
            Err(_e) => {
                self.attach_points = self
                    .attach_points
                    .iter()
                    .map(|ap| format!("{}{}", ARCH_SYSCALL_PREFIX, ap))
                    .collect();
                self.attach_probes()
            }
        }
    }

    fn attach_probes(&self) -> Result<(Vec<String>, Vec<RawFd>), OxidebpfError> {
        if !self.loaded {
            return Err(OxidebpfError::ProgramNotLoaded);
        }

        match self.kind {
            ProgramType::Kprobe | ProgramType::Kretprobe => self.attach_kprobe(),
            ProgramType::Uprobe | ProgramType::Uretprobe => self.attach_uprobe(),
            _ => Err(OxidebpfError::UnsupportedProgramType),
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

impl ProgramGroup<'_> {
    /// Create a program group out of multiple [`ProgramVersion`](struct@ProgramVersion)s.
    ///
    /// Together with [`load()`](fn.load.html), this is the primary public interface of the
    /// oxidebpf library. You feed your `ProgramGroup` a collection of `ProgramVersion`s,
    /// each with their own set of `Program`s. Note that you must provide your `ProgramGroup`
    /// with a [`ProgramBlueprint`](struct@ProgramBlueprint). The blueprint contains the parsed
    /// object file with all the eBPF programs and maps you may load.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::blueprint::ProgramBlueprint;
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
    /// ProgramGroup::new(
    ///     program_blueprint,
    ///     vec![ProgramVersion::new(vec![Program::new(
    ///         ProgramType::Kprobe,
    ///         "test_program",
    ///         vec!["do_mount"],
    ///     ).syscall(true)])],
    ///     None,
    /// );
    /// ```
    pub fn new(
        program_blueprint: ProgramBlueprint,
        program_versions: Vec<ProgramVersion>,
        event_buffer_size: Option<usize>,
    ) -> ProgramGroup {
        let event_buffer_size = event_buffer_size.unwrap_or(1024);
        let (tx, rx): (Sender<PerfChannelMessage>, Receiver<PerfChannelMessage>) =
            bounded(event_buffer_size);
        let channel = Channel { tx, rx };
        ProgramGroup {
            program_blueprint,
            program_versions,
            event_buffer_size,
            channel,
        }
    }

    /// Attempt to load contained [`ProgramVersion`](struct@ProgramVersion)s until one
    /// successfully loads.
    ///
    /// This function attempts to load each `ProgramVersion` in the order given until
    /// one successfully loads. When one loads, if that version had a perfmap channel,
    /// a [`PerfChannelMessage`](struct@PerfChannelMessage) receiver crossbeam channel
    /// is returned. If none load, a `NoProgramVersionLoaded` error is returned, along
    /// with all the internal errors generated during attempted loading.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::blueprint::ProgramBlueprint;
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
    ///     program_blueprint,
    ///     vec![ProgramVersion::new(vec![Program::new(
    ///         ProgramType::Kprobe,
    ///         "test_program",
    ///         vec!["do_mount"],
    ///     ).syscall(true)])],
    ///     None,
    /// );
    ///
    /// program_group.load().expect("Could not load programs");
    /// ```
    pub fn load(&mut self) -> Result<Option<Receiver<PerfChannelMessage>>, OxidebpfError> {
        let mut errors = Vec::<OxidebpfError>::new();
        for program_version in self.program_versions.iter_mut() {
            match program_version.load_program_version(
                self.program_blueprint.to_owned(),
                self.channel.clone(),
                self.event_buffer_size,
            ) {
                Ok(r) => return Ok(r),
                Err(e) => errors.push(e),
            };
        }
        Err(OxidebpfError::NoProgramVersionLoaded(errors))
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
    ///         ProgramType::Kprobe,
    ///         "sys_ptrace_write",
    ///         vec!["sys_ptrace"],
    ///     ).syscall(true),
    ///     Program::new(
    ///         ProgramType::Kprobe,
    ///         "sys_process_vm_writev",
    ///         vec!["sys_process_vm_writev"],
    ///     ).syscall(true)
    /// ];
    ///
    /// ProgramVersion::new(program_vec);
    /// ```
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::<RawFd>::new(),
            ev_names: HashSet::<String>::new(),
        }
    }

    fn event_poller(
        &self,
        perfmaps: Vec<PerfMap>,
        tx: Sender<PerfChannelMessage>,
    ) -> Result<(), OxidebpfError> {
        std::thread::Builder::new()
            .name("PerfMapPoller".to_string())
            .spawn(move || {
                let mut poll = Poll::new()
                    .map_err(|e| OxidebpfError::EbpfPollerError(e.to_string()))
                    .expect("could not create poller");
                let tokens: HashMap<Token, &PerfMap> = perfmaps
                    .iter()
                    .map(|p: &PerfMap| -> Result<(Token, &PerfMap), OxidebpfError> {
                        let token = Token(p.ev_fd as usize);
                        poll.registry()
                            .register(&mut SourceFd(&p.ev_fd), token, Interest::READABLE)
                            .map_err(|e| OxidebpfError::EbpfPollerError(e.to_string()))?;

                        Ok((token, p))
                    })
                    .collect::<Result<HashMap<Token, &PerfMap>, OxidebpfError>>()
                    .expect("could not establish polling registry");
                let mut events = Events::with_capacity(1024);
                'outer: loop {
                    match poll.poll(&mut events, Some(Duration::from_millis(100))) {
                        Ok(_) => {}
                        Err(e) => match nix::errno::Errno::from_i32(nix::errno::errno()) {
                            Errno::EINTR => continue,
                            _ => {
                                panic!("unrecoverable polling error: {}", e)
                            }
                        },
                    }
                    let events: Vec<(String, i32, Result<Option<PerfEvent>, OxidebpfError>)> =
                        events
                            .iter()
                            .filter(|event| event.is_readable())
                            .filter_map(|e| tokens.get(&e.token()))
                            .map(|perfmap| {
                                (perfmap.name.clone(), perfmap.cpuid() as i32, perfmap.read())
                            })
                            .collect();
                    for event in events.into_iter() {
                        let message = match event.2 {
                            Ok(None) => continue,
                            Ok(Some(PerfEvent::Lost(_))) => continue, // TODO: count losses
                            Ok(Some(PerfEvent::Sample(e))) => {
                                PerfChannelMessage(event.0, event.1, e.data.clone())
                            }
                            Err(_) => continue, // ignore any errors
                        };
                        match tx.send(message) {
                            Ok(_) => {}
                            Err(_) => break 'outer,
                        };
                    }
                }
            })
            .map_err(|_e| OxidebpfError::ThreadPollingError)?;
        Ok(())
    }

    fn load_program_version(
        &mut self,
        mut program_blueprint: ProgramBlueprint,
        channel: Channel,
        event_buffer_size: usize,
    ) -> Result<Option<Receiver<PerfChannelMessage>>, OxidebpfError> {
        let mut matching_blueprints: Vec<ProgramObject> = self
            .programs
            .iter()
            .map(|p| {
                program_blueprint
                    .programs
                    .get(&*p.name)
                    .ok_or(OxidebpfError::ProgramNotFound)
            })
            .collect::<Result<Vec<&ProgramObject>, OxidebpfError>>()?
            .into_iter()
            .map(|p| p.to_owned())
            .collect();
        let mut perfmaps = Vec::<PerfMap>::new();
        // load maps and save fds and apply relocations
        let mut loaded_maps = HashSet::<String>::new();
        for program_object in matching_blueprints.iter_mut() {
            for name in program_object.required_maps().iter() {
                let map = program_blueprint
                    .maps
                    .get_mut(name)
                    .ok_or(OxidebpfError::MapNotFound)?;

                if !loaded_maps.contains(&map.name.clone()) {
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
                            let mut perfmap =
                                PerfMap::new_group(&map.name, event_attr, event_buffer_size)?;
                            perfmap
                                .iter()
                                .map(|p: &PerfMap| -> Result<(), OxidebpfError> {
                                    self.fds.insert(p.ev_fd as RawFd);
                                    bpf_map_update_elem::<i32, i32>(fd, p.cpuid(), p.ev_fd as i32)
                                })
                                .collect::<Result<Vec<()>, OxidebpfError>>()?;

                            perfmaps.append(&mut perfmap);
                        }
                        _ => {
                            let fd =
                                unsafe { syscall::bpf_map_create_with_sized_attr(sized_attr)? };
                            self.fds.insert(fd);
                            program_object.fixup_map_relocation(fd, map)?;
                        }
                    }
                    loaded_maps.insert(map.name.clone());
                } else {
                    program_object.fixup_map_relocation(map.get_fd()?, map)?;
                }
            }
        }

        // load and attach programs
        for blueprint in matching_blueprints.iter() {
            let fd = syscall::bpf_prog_load(
                u32::from(&blueprint.program_type),
                &blueprint.code,
                blueprint.license.clone(),
                blueprint.kernel_version,
            );
            // Programs are kept separate from ProgramBlueprints to allow users to specify
            // different blueprints/files for the same set of programs, should they choose.
            // This means we need to do ugly filters like this.
            let programs: Vec<&mut Program> = self
                .programs
                .iter_mut()
                .filter(|p| p.name.eq(blueprint.name.as_str()))
                .collect();
            if let Err(e) = fd {
                for program in programs.iter() {
                    if !program.optional {
                        // If any are not optional, fail out of the whole Version
                        return Err(e);
                    }
                }
                // if they're all optional, go to the next blueprint object
                continue;
            }
            let fd = fd?;
            for p in programs {
                p.loaded_as(fd);
                match p.attach() {
                    Err(e) => {
                        if !p.optional {
                            return Err(e);
                        }
                    }
                    Ok(s) => {
                        for s in s.0.iter() {
                            self.ev_names.insert(s.clone());
                        }
                        for fd in s.1.into_iter() {
                            self.fds.insert(fd);
                        }
                    }
                }
            }
            self.fds.insert(fd);
        }

        // start event poller and pass back channel, if one exists
        if perfmaps.is_empty() {
            Ok(None)
        } else {
            self.event_poller(perfmaps, channel.tx)?;
            Ok(Some(channel.rx))
        }
    }
}

impl<'a> Drop for ProgramVersion<'a> {
    fn drop(&mut self) {
        // Detach everything, close remaining attachpoints
        for fd in self.fds.iter() {
            unsafe {
                libc::close(*fd as c_int);
            }
        }

        // We are intentionally enumerating and closing _all_ debugfs created
        // probes here, on the off chance that one gets missed somehow. Otherwise,
        // we might end up stuck with a bunch of unused probes clogging the namespace.
        // If it has _oxidebpf_ it's probably one of ours. This avoids conflicting
        // with customer user probes or probes from other frameworks.

        // uprobe
        let up_file = std::fs::OpenOptions::new()
            .append(true)
            .write(true)
            .read(true)
            .open("/sys/kernel/debug/tracing/uprobe_events")
            .unwrap(); // if we can't drop - panic!
        let up_reader = BufReader::new(&up_file);
        let mut up_writer = BufWriter::new(&up_file);
        for line in up_reader.lines() {
            let line = line.unwrap();
            if line.contains("_oxidebpf_") {
                up_writer
                    .write_all(format!("-:{}\n", &line[2..]).as_bytes())
                    .unwrap();
            }
        }
        // kprobe
        let kp_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .open("/sys/kernel/debug/tracing/kprobe_events")
            .unwrap(); // if we can't drop - panic!
        let kp_reader = BufReader::new(&kp_file);
        let mut kp_writer = BufWriter::new(&kp_file);
        for line in kp_reader.lines() {
            let line = line.unwrap();
            if line.contains("_oxidebpf_") {
                kp_writer
                    .write_all(format!("-:{}\n", &line[2..]).as_bytes())
                    .unwrap();
            }
        }
    }
}

#[cfg(test)]
mod program_tests {
    use std::path::PathBuf;

    use crate::blueprint::ProgramBlueprint;
    use crate::ProgramType;
    use crate::{Program, ProgramGroup, ProgramVersion};

    #[test]
    fn test_program_group() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new(
            program_blueprint,
            vec![ProgramVersion::new(vec![
                Program::new(
                    ProgramType::Kprobe,
                    "test_program_map_update",
                    vec!["do_mount"],
                )
                .syscall(true),
                Program::new(ProgramType::Kprobe, "test_program", vec!["do_mount"]).syscall(true),
            ])],
            None,
        );

        program_group.load().expect("Could not load programs");
    }
}

/// An enum of the different BPF program types.
#[derive(Debug, Clone, PartialEq)]
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
