#![allow(dead_code)]
use crate::blueprint::{EbpfObject, ProgramBlueprint, ProgramObject};
use crate::bpf::ProgramType;
use crate::error::OxidebpfError;
use crate::maps::{PerfMap, ProgramMap};
use crate::probes::{KProbe, UProbe};
use crossbeam_channel::{bounded, Receiver, Sender};
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
    // TODO: add kprobe/uprobe
}

impl Program {
    fn get_name(&self) -> String {
        match self {
            Program::KProbe { name, .. } => name.clone(),
            Program::UProbe { name, .. } => name.clone(),
        }
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

    pub fn load(&self) -> RawFd {
        #![allow(unused_variables)]
        match self {
            Program::KProbe { kprobe, .. } => {
                unimplemented!()
            }
            Program::UProbe { uprobe, .. } => {
                unimplemented!()
            }
        };
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

    pub fn load(&self) -> Result<Option<Receiver<&[u8]>>, OxidebpfError> {
        for program_version in self.program_versions.iter() {
            let matching_blueprints: Vec<Vec<&EbpfObject>> = program_version
                .programs
                .iter()
                .map(|program| {
                    let matching_objects: Vec<&EbpfObject> = self
                        .program_blueprint
                        .objects
                        .iter()
                        .filter(|object| match object {
                            EbpfObject::Program(p) => {
                                p.name == program.name && p.kind == program.kind
                            }
                            _ => false,
                        })
                        .collect();
                    matching_objects
                })
                .collect();
            let matching_blueprints: Vec<&ProgramObject> = {
                let mut tmp = Vec::new();
                for blueprint in matching_blueprints {
                    for obj in blueprint {
                        match obj {
                            EbpfObject::Map(_) => {}
                            EbpfObject::Program(p) => tmp.push(p),
                        }
                    }
                }
                tmp
            };
            // find associated maps by section_name
            let mut required_maps = Vec::<&String>::new();
            matching_blueprints.iter().for_each(|blueprint| {
                blueprint
                    .required_maps()
                    .iter()
                    .for_each(|name| required_maps.push(name))
            });

            // load associated maps
        }
        Ok(None)
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
