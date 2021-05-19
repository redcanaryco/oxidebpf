use crate::probes::Probe;
use crate::maps::Map;

pub mod maps;
pub mod probes;

pub struct Module {

}

// Looks like I'm using Program where cwp-ebpf uses ProgramGroup and ProgramGroup
// where cwp-ebpf uses ProgramGroupVersion
pub struct Program<'a, T: Probe<'a>> {
    group: ProgramGroup<'a, T>,
}

pub struct ProgramData {

}

pub enum Event {

}

pub struct ProgramGroup<'a, T: Probe<'a>> {
    probes: Vec<T>,
    map: Vec<&'a str>,
}

impl Module {
    pub fn parse() -> Module {
        unimplemented!()
    }
}

impl<'a, T: Probe<'a>> Program<'a, T> {
    // do we want to put the logic for try-load-unload-try here?
    pub fn new() -> Program<'a, T> {
        unimplemented!()
    }

    pub fn data() {
        unimplemented!()
    }

    pub fn data_mut() {
        unimplemented!()
    }

    pub fn load() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
