#![allow(dead_code)]
use crate::blueprint::{MapObject, ProgramBlueprint, ProgramObject};
use crate::bpf::constant::bpf_map_type;
use crate::bpf::ProgramType;
use crate::error::OxidebpfError;
use crate::maps::{PerfMap, ProgramMap};
use crate::probes::{KProbe, UProbe};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::rc::Rc;

mod blueprint;
mod bpf;
mod error;
pub mod maps;
pub mod probes;

// TODO: this is the public interface, needs docstrings

struct Channel<'a> {
    tx: Sender<&'a [u8]>,
    rx: Receiver<&'a [u8]>,
}

pub struct ProgramGroup<'a> {
    // TODO: pass up channel from perfmap(s) (if any) so user can get raw bytes
    program_blueprint: ProgramBlueprint,
    program_versions: Vec<ProgramVersion>,
    event_buffer_size: Option<usize>,
    channel: Channel<'a>,
}

pub struct ProgramVersion {
    programs: Vec<Program>,
}

pub struct Program {
    kind: ProgramType,
    name: String,
    optional: bool,
    program_object: ProgramObject,
    loaded: bool,
    fd: RawFd,
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
        //bpf::syscall::bpf_prog_load(self.program_object.program_type as u32)
    }

    fn get_fd() -> RawFd {
        unimplemented!()
    }
}

impl<'a> ProgramGroup<'a> {
    // TODO: try-load-fail-try-next logic goes here
    pub fn new(
        program_blueprint: ProgramBlueprint,
        program_versions: Vec<ProgramVersion>,
        event_buffer_size: Option<usize>,
    ) -> ProgramGroup<'a> {
        let (tx, rx): (Sender<&'a [u8]>, Receiver<&'a [u8]>) =
            bounded(event_buffer_size.unwrap_or(1024));
        let channel = Channel { tx, rx };
        ProgramGroup {
            program_blueprint,
            program_versions,
            event_buffer_size,
            channel,
        }
    }

    fn load_program_version(
        &self,
        program_version: &ProgramVersion,
    ) -> Result<Option<Receiver<&[u8]>>, OxidebpfError> {
        let mut matching_blueprints = Vec::<ProgramObject>::new();
        for mut program in program_version.programs.iter() {
            matching_blueprints.push(
                self.program_blueprint
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
                let map = self
                    .program_blueprint
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
            }
        }

        // load programs
        for blueprint in matching_blueprints.iter() {
            bpf::syscall::bpf_prog_load(
                u32::from(&blueprint.program_type),
                &blueprint.code,
                blueprint.license.clone(),
            )?;
        }
        Ok(None)
    }

    pub fn load(&self) -> Result<Option<Receiver<&[u8]>>, OxidebpfError> {
        let mut loaded = false;
        for mut program_version in self.program_versions.iter() {
            match self.load_program_version(program_version) {
                Ok(r) => {
                    loaded = true;
                    return Ok(r);
                }
                Err(_) => {}
            };
        }
        Err(OxidebpfError::NoProgramVersionLoaded)
    }
}

impl ProgramVersion {
    pub fn new(programs: Vec<Program>) -> ProgramVersion {
        ProgramVersion { programs }
    }
    // TODO: try-load-fail-bail logic goes here
}

impl Drop for ProgramVersion {
    fn drop(&mut self) {
        // Detach everything, close remaining attachpoints
        todo!()
    }
}
