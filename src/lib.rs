#![allow(dead_code)]

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::os::unix::io::RawFd;
use std::slice;
use std::thread::JoinHandle;

use crossbeam_channel::{bounded, Receiver, SendError, Sender};

use perf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup};

use crate::blueprint::{ProgramBlueprint, ProgramObject};
use crate::bpf::constant::bpf_map_type;
use crate::bpf::syscall::{attach_kprobe, attach_uprobe};
use crate::bpf::{syscall, BpfAttr, MapConfig, ProgramType, SizedBpfAttr};
use crate::error::OxidebpfError;
use crate::maps::{PerCpu, PerfMap};
use crate::maps::{PerfEvent, ProgramMap};
use crate::perf::constant::{perf_event_sample_format, perf_sw_ids, perf_type_id};

mod blueprint;
mod bpf;
mod error;
pub mod maps;
mod perf;
pub mod probes;

#[cfg(target_arch = "aarch64")]
const ARCH_SYSCALL_PREFIX: &str = "__arm64__";
#[cfg(target_arch = "x86_64")]
const ARCH_SYSCALL_PREFIX: &str = "__x64__";

// TODO: this is the public interface, needs docstrings

// (map name, cpuid, event data)
pub struct PerfChannelMessage(String, i32, Vec<u8>);

#[derive(Clone)]
struct Channel {
    tx: Sender<PerfChannelMessage>,
    rx: Receiver<PerfChannelMessage>,
}

pub struct ProgramGroup<'a> {
    program_blueprint: ProgramBlueprint,
    program_versions: Vec<ProgramVersion<'a>>,
    event_buffer_size: usize,
    channel: Channel,
}

pub struct ProgramVersion<'a> {
    programs: Vec<Program<'a>>,
    fds: HashSet<RawFd>,
}

pub struct Program<'a> {
    kind: ProgramType,
    name: &'a str,
    attach_points: Vec<&'a str>,
    optional: bool,
    loaded: bool,
    fd: RawFd,
}

impl<'a> Program<'a> {
    fn get_name(&self) -> &'a str {
        self.name
    }

    pub fn new(
        kind: ProgramType,
        name: &'a str,
        attach_points: Vec<&'a str>,
        optional: bool,
    ) -> Program<'a> {
        Self {
            kind,
            name,
            attach_points,
            optional,
            loaded: false,
            fd: 0,
        }
    }

    fn attach_kprobe(&self) -> Result<(), OxidebpfError> {
        let mut errs = Vec::<OxidebpfError>::new();
        self.attach_points.iter().map(|attach_point| {
            if let Err(e) = attach_kprobe(self.fd, attach_point, None) {
                errs.push(e);
                if let Err(e) = attach_kprobe(
                    self.fd,
                    &format!("{}{}", ARCH_SYSCALL_PREFIX, attach_point),
                    None,
                ) {
                    errs.push(e);
                }
            }
        });

        if errs.is_empty() {
            Ok(())
        } else {
            Err(OxidebpfError::MultipleErrors(errs))
        }
    }

    fn attach_uprobe(&self) -> Result<(), OxidebpfError> {
        let mut errs = Vec::<OxidebpfError>::new();
        self.attach_points.iter().map(|attach_point| {
            if let Err(e) = attach_uprobe(self.fd, attach_point, None) {
                errs.push(e)
            }
        });
        if errs.is_empty() {
            Ok(())
        } else {
            Err(OxidebpfError::MultipleErrors(errs))
        }
    }

    fn attach(&self) -> Result<(), OxidebpfError> {
        if !self.loaded {
            return Err(OxidebpfError::ProgramNotLoaded);
        }

        let ret = match self.kind {
            ProgramType::Kprobe | ProgramType::Kretprobe => self.attach_kprobe(),
            ProgramType::Uprobe | ProgramType::Uretprobe => self.attach_uprobe(),
            _ => Err(OxidebpfError::UnsupportedProgramType),
        };

        // if we're optional, then ignore any errors
        if self.optional {
            Ok(())
        } else {
            ret
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
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::<RawFd>::new(),
        }
    }

    fn event_poller(&self, perfmaps: Vec<PerfMap>, tx: Sender<PerfChannelMessage>) {
        std::thread::Builder::new()
            .name("PerfMapPoller".to_string())
            .spawn(move || 'outer: loop {
                for perfmap in perfmaps.iter() {
                    let message = match perfmap.read() {
                        None => continue,
                        Some(PerfEvent::Lost(_)) => continue, // TODO: count losses
                        Some(PerfEvent::Sample(e)) => PerfChannelMessage(
                            perfmap.name.clone(),
                            perfmap.cpuid() as i32,
                            Vec::from(e.data),
                        ),
                    };
                    match tx.send(message) {
                        Ok(_) => {}
                        Err(_) => break 'outer,
                    };
                }
            });
    }

    fn load_program_version(
        &mut self,
        program_blueprint: ProgramBlueprint,
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
                    .get(name)
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
                            perfmaps.append(&mut perfmap);
                            perfmap.iter().for_each(|p| {
                                self.fds.insert(p.ev_fd as RawFd);
                            });
                        }
                        _ => {
                            let fd =
                                unsafe { syscall::bpf_map_create_with_sized_attr(sized_attr)? };
                            self.fds.insert(fd);
                            program_object.fixup_map_relocation(fd, map)?;
                        }
                    }
                    loaded_maps.insert(map.name.clone());
                }
            }
        }

        // load and attach programs
        for blueprint in matching_blueprints.iter() {
            self.fds.insert({
                let fd = syscall::bpf_prog_load(
                    u32::from(&blueprint.program_type),
                    &blueprint.code,
                    blueprint.license.clone(),
                )? as RawFd;
                // Programs are kept separate from ProgramBlueprints to allow users to specify
                // different blueprints/files for the same set of programs, should they choose.
                // This means we need to do ugly filters like this.
                self.programs
                    .iter_mut()
                    .filter(|p| p.name.eq(blueprint.name.as_str()))
                    .map(|p| {
                        p.loaded_as(fd);
                        p.attach()
                    })
                    .collect::<Result<Vec<()>, OxidebpfError>>()?;
                fd
            });
        }

        // start event poller and pass back channel, if one exists
        if perfmaps.is_empty() {
            Ok(None)
        } else {
            self.event_poller(perfmaps, channel.tx);
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
    }
}

#[cfg(test)]
mod program_tests {
    use std::path::PathBuf;

    use crate::blueprint::ProgramBlueprint;
    use crate::bpf::ProgramType;
    use crate::{Program, ProgramGroup, ProgramVersion};

    #[test]
    fn test_program_group() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test.o");
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(d).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new(
            program_blueprint,
            vec![ProgramVersion::new(vec![Program::new(
                ProgramType::Kprobe,
                "sys_ptrace_write",
                vec!["sys_ptrace"],
                false,
            )])],
            None,
        );

        program_group.load().expect("Could not load programs");
    }
}
