#![allow(dead_code)]
use crate::blueprint::{ProgramBlueprint, ProgramObject};
use crate::bpf::constant::bpf_map_type;
use crate::bpf::{PerfBpAddr, PerfBpLen, PerfEventAttr, PerfSample, PerfWakeup, ProgramType};
use crate::error::OxidebpfError;
use crate::maps::Event;
use crate::maps::PerfMap;
use crossbeam_channel::{bounded, Receiver, SendError, Sender};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::os::raw::c_int;
use std::os::unix::io::RawFd;
use std::slice;
use std::thread::JoinHandle;

mod blueprint;
mod bpf;
mod error;
pub mod maps;
pub mod probes;

// TODO: this is the public interface, needs docstrings

#[derive(Clone)]
struct Channel {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

pub struct ProgramGroup {
    // TODO: pass up channel from perfmap(s) (if any) so user can get raw bytes
    program_blueprint: ProgramBlueprint,
    program_versions: Vec<ProgramVersion>,
    event_buffer_size: Option<usize>,
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
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) =
            bounded(event_buffer_size.unwrap_or(1024));
        let channel = Channel { tx, rx };
        ProgramGroup {
            program_blueprint,
            program_versions,
            event_buffer_size,
            channel,
        }
    }

    pub fn load(&mut self) -> Result<Option<Receiver<Vec<u8>>>, OxidebpfError> {
        let mut errors = Vec::<OxidebpfError>::new();
        for program_version in self.program_versions.iter_mut() {
            match program_version
                .load_program_version(self.program_blueprint.to_owned(), self.channel.clone())
            {
                Ok(r) => return Ok(r),
                Err(e) => errors.push(e),
            };
        }
        Err(OxidebpfError::NoProgramVersionLoaded(errors))
    }
}

impl ProgramVersion {
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::<RawFd>::new(),
        }
    }

    fn event_poller(&self, perfmaps: Vec<PerfMap>, tx: Sender<Vec<u8>>) {
        std::thread::spawn(move || 'outer: loop {
            for perfmap in perfmaps.iter() {
                let event = perfmap.read();
                let event = match event {
                    None => continue,
                    Some(e) => e,
                };
                let event = match event {
                    Event::Some(e) => e,
                    Event::Lost => continue,
                };
                match tx.send(event.data) {
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
    ) -> Result<Option<Receiver<Vec<u8>>>, OxidebpfError> {
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
        let mut map_fds = HashMap::<String, RawFd>::new();
        for blueprint in matching_blueprints.iter_mut() {
            for name in blueprint.required_maps().iter() {
                let map = program_blueprint
                    .maps
                    .get(name)
                    .ok_or(OxidebpfError::MapNotFound)?;
                let map_fd = match map.definition.map_type {
                    bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                        // TODO load perfmap and make/save channel to return
                        let fd = bpf::syscall::bpf_map_create_with_config(map.definition)?;
                        let mut perfmap = PerfMap::new_group(
                            &blueprint.name,
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
                        )?;
                        perfmaps.append(&mut perfmap);
                        fd
                    }
                    _ => {
                        if map_fds.contains_key(&map.name.clone()) {
                            map_fds
                                .get(&map.name.clone())
                                .ok_or(OxidebpfError::MapNotFound)?
                                .to_owned()
                        } else {
                            bpf::syscall::bpf_map_create_with_config(map.definition)?
                        }
                    }
                };
                blueprint.fixup_map_relocation(map_fd, map)?;
                map_fds.insert(map.name.clone(), map_fd);
                self.fds.insert(map_fd);
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
    use crate::blueprint::ProgramBlueprint;
    use crate::bpf::ProgramType;
    use crate::{Program, ProgramGroup, ProgramVersion};
    use std::path::PathBuf;

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
