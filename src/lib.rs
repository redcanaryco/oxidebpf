use crate::probes::{KProbe, UProbe};
use crate::maps::{Map, RWMap, ProgramMap, PerfMap};
use std::marker::PhantomData;
use std::borrow::Borrow;
use std::rc::Rc;
use std::os::unix::io::RawFd;

pub mod maps;
pub mod probes;
mod bpf;


// TODO: this is the public interface, needs docstrings

pub struct ProgramBlueprint {
    // TODO: ELF parser goes here
}

pub struct ProgramGroup {
    // TODO: pass up channel from perfmap(s) (if any) so user can get raw bytes
    program_versions: Vec<ProgramVersion>,
}

pub struct ProgramVersion {
    programs: Vec<Rc<Program>>,
    maps: Vec<Rc<Box<dyn ProgramMap>>>,
    perf_maps: Vec<Rc<PerfMap>>,
}

pub enum Program {
    KProbe{
        kprobe: KProbe,
        optional: bool,
    },
    UProbe{
        uprobe: UProbe,
        optional: bool,
    },
}

impl ProgramBlueprint {
    // TODO: ELF parser impl goes here
    pub fn new() -> ProgramBlueprint {
        unimplemented!()
    }
}

impl Program {
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
        match self {
            Program::KProbe{kprobe, ..} => {
                unimplemented!()
            },
            Program::UProbe {uprobe, ..} => {
                unimplemented!()
            }
        };
    }

    fn get_fd() -> RawFd {
        unimplemented!()
    }
}

impl ProgramGroup {
    // TODO: try-load-fail-try-next logic goes here
}

impl ProgramVersion {
    // TODO: try-load-fail-bail logic goes here
}

impl Drop for ProgramVersion {
    fn drop(&mut self) {
        // Detach everything, close remaining attachpoints
        todo!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
