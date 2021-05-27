#![allow(dead_code)]
use crate::blueprint::{ProgramBlueprint, ProgramObject};
use crate::bpf::constant::bpf_map_type;
use crate::bpf::ProgramType;
use crate::error::OxidebpfError;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::os::raw::c_int;
use std::os::unix::io::RawFd;

mod blueprint;
mod bpf;
mod error;
pub mod maps;
pub mod probes;

// TODO: this is the public interface, needs docstrings

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

    pub fn load(&mut self) -> Result<Option<Receiver<&[u8]>>, OxidebpfError> {
        for program_version in self.program_versions.iter_mut() {
            if let Ok(r) = program_version.load_program_version(self.program_blueprint.to_owned()) {
                return Ok(r);
            };
        }
        Err(OxidebpfError::NoProgramVersionLoaded)
    }
}

impl ProgramVersion {
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion {
            programs,
            fds: HashSet::<RawFd>::new(),
        }
    }

    fn load_program_version(
        &mut self,
        program_blueprint: ProgramBlueprint,
    ) -> Result<Option<Receiver<&[u8]>>, OxidebpfError> {
        let mut matching_blueprints = Vec::<ProgramObject>::new();
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
                        0
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
        Ok(None)
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

    #[test]
    fn test_program_group() {
        let program_blueprint = ProgramBlueprint::new(
            &std::fs::read("./test_obj/test.o").expect("Could not open file"),
            None,
        )
        .expect("Could not open test object file");
        let program_group = ProgramGroup::new(
            program_blueprint,
            vec![ProgramVersion::new(vec![Program {
                kind: ProgramType::Kprobe,
                name: "".to_string(),
                optional: false,
                loaded: false,
            }])],
            None,
        );
    }
}
