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
use crate::bpf::{MapConfig, ProgramType};
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

// TODO: this is the public interface, needs docstrings

// (map name, cpuid, event data)
pub struct PerfChannelMessage(String, i32, Vec<u8>);

#[derive(Clone)]
struct Channel {
    tx: Sender<PerfChannelMessage>,
    rx: Receiver<PerfChannelMessage>,
}

pub struct ProgramGroup {
    // TODO: pass up channel from perfmap(s) (if any) so user can get raw bytes
    program_blueprint: ProgramBlueprint,
    program_versions: Vec<ProgramVersion>,
    event_buffer_size: usize,
    channel: Channel,
}

pub struct ProgramVersion {
    programs: Vec<Program>,
    fds: HashSet<RawFd>,
}

pub struct Program {
    kind: ProgramType,
    name: String,
    optional: bool,
    loaded: bool,
}

impl Program {
    fn get_name(&self) -> &String {
        &self.name
    }
    // TODO: Figure out what's inside Program, load/unload, manage fd, drop, etc
    pub fn new() -> Program {
        unimplemented!()
    }

    pub fn data(&self) {
        unimplemented!()
    }

    pub fn data_mut(&self) {
        unimplemented!()
    }

    fn load(&self) {
        todo!()
    }

    fn get_fd() -> RawFd {
        unimplemented!()
    }
}

impl ProgramGroup {
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

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

impl ProgramVersion {
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::<RawFd>::new(),
        }
    }

    fn event_poller(&self, perfmaps: Vec<PerfMap>, tx: Sender<PerfChannelMessage>) {
        std::thread::spawn(move || 'outer: loop {
            for perfmap in perfmaps.iter() {
                let event = perfmap.read();
                let event = match event {
                    None => continue,
                    Some(e) => e,
                };
                let event = match event {
                    PerfEvent::Sample(e) => e,
                    PerfEvent::Lost(_) => continue,
                };
                let message = PerfChannelMessage(
                    perfmap.name.clone(),
                    perfmap.cpuid() as i32,
                    Vec::from(event.data),
                );
                unsafe {
                    match tx.send(message) {
                        Ok(_) => {}
                        Err(_) => break 'outer,
                    };
                }
            }
        });
    }

    fn load_program_version(
        &mut self,
        program_blueprint: ProgramBlueprint,
        channel: Channel,
        event_buffer_size: usize,
    ) -> Result<Option<Receiver<PerfChannelMessage>>, OxidebpfError> {
        let mut matching_blueprints = Vec::<ProgramObject>::new();
        let mut perfmaps = Vec::<PerfMap>::new();
        for program in self.programs.iter() {
            matching_blueprints.push(
                program_blueprint
                    .programs
                    .get(&*program.name)
                    .ok_or(OxidebpfError::ProgramNotFound)?
                    .to_owned(),
            );
        }

        // load maps and save fds and apply relocations
        let mut loaded_maps = HashSet::<String>::new();
        for program_object in matching_blueprints.iter_mut() {
            for name in program_object.required_maps().iter() {
                let map = program_blueprint
                    .maps
                    .get(name)
                    .ok_or(OxidebpfError::MapNotFound)?;

                if !loaded_maps.contains(&map.name.clone()) {
                    match map.definition.map_type {
                        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                            let fd = bpf::syscall::bpf_map_create_with_config(MapConfig::from(
                                map.definition,
                            ))?;
                            program_object.fixup_map_relocation(fd, map)?;

                            let event_attr = MaybeUninit::<PerfEventAttr>::zeroed();
                            let mut event_attr = unsafe { event_attr.assume_init() };
                            event_attr.config = perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as u64;
                            event_attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
                            event_attr.p_type = perf_type_id::PERF_TYPE_SOFTWARE;
                            event_attr.sample_type =
                                perf_event_sample_format::PERF_SAMPLE_RAW as u64;
                            event_attr.sample_union = PerfSample { sample_period: 1 };
                            event_attr.wakeup_union = PerfWakeup { wakeup_events: 1 };
                            let mut perfmap =
                                PerfMap::new_group(&map.name, event_attr, event_buffer_size)?;
                            perfmaps.append(&mut perfmap);
                            perfmap.iter().for_each(|p| {
                                self.fds.insert(p.ev_fd as RawFd);
                            });
                        }
                        _ => {
                            let fd = bpf::syscall::bpf_map_create_with_config(MapConfig::from(
                                map.definition,
                            ))?;
                            program_object.fixup_map_relocation(fd, map)?;
                            self.fds.insert(fd);
                        }
                    }
                    loaded_maps.insert(map.name.clone());
                }
            }
        }

        // load programs
        for blueprint in matching_blueprints.iter() {
            self.fds.insert(bpf::syscall::bpf_prog_load(
                u32::from(&blueprint.program_type),
                &blueprint.code,
                blueprint.license.clone(),
            )?);
        }

        // start event poller, if one exists
        // pass back channel, if it exists
        if perfmaps.is_empty() {
            Ok(None)
        } else {
            self.event_poller(perfmaps, channel.tx);
            Ok(Some(channel.rx))
        }
    }
}

impl Drop for ProgramGroup {
    fn drop(&mut self) {
        for program_version in self.program_versions.iter_mut() {
            std::mem::drop(program_version);
        }
    }
}

impl Drop for ProgramVersion {
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
        // TODO: currently fails with E2BIG
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/test.o");
        let program_blueprint =
            ProgramBlueprint::new(&std::fs::read(d).expect("Could not open file"), None)
                .expect("Could not open test object file");
        let mut program_group = ProgramGroup::new(
            program_blueprint,
            vec![ProgramVersion::new(vec![Program {
                kind: ProgramType::Kprobe,
                name: "sys_ptrace_write".to_string(),
                optional: false,
                loaded: false,
            }])],
            None,
        );

        program_group.load().expect("Could not load programs");
    }
}
