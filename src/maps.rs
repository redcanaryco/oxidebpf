use std::any::Any;
use std::error::Error;
use std::marker::PhantomData;
use std::os::unix::io::RawFd;

pub struct PerfMap {
    // TODO: perfmap functions
    name: String,
    ev_fds: Vec<RawFd>,
    ev_names: Vec<String>,
}

pub struct ArrayMap<'a, T: 'a> {
    // TODO: read/write functions
    base: Map<&'a T>,
}

pub struct Map<T> {
    // TODO: Map fields
    _t: PhantomData<T>,
}

pub trait ProgramMap {
    fn load(&self) -> Result<(), Box<dyn Error>>;
    fn unload(&self) -> Result<(), Box<dyn Error>>;
    fn get_fd(&self) -> RawFd; // if we don't (need to) track attachpoints this doesn't need to be exposed
}

pub trait RWMap<T> {
    fn read(&self) -> Result<T, Box<dyn Error>>;
    fn write(&self) -> Result<(), Box<dyn Error>>;
}

pub trait PerCpu {
    // What other per-cpu maps are there that we may want to use?
    fn cpuid(&self) -> u32;
}

impl PerfMap {
    // we want cpuid and give back a channel to read from
    pub fn new() -> PerfMap {
        unimplemented!()
    }

    pub fn bind(&self) {
        // superseded by `load()`? - check
        unimplemented!()
    }

    pub fn get_channel(&self) {
        // TODO: every event out of the channel is some Event::Lost() or Event::Sample() of raw
        // bytes, implement, we want to return events+cpuid
        unimplemented!()
    }
}

impl PerCpu for PerfMap {
    fn cpuid(&self) -> u32 {
        todo!()
    }
}

impl ProgramMap for PerfMap {
    fn load(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn unload(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn get_fd(&self) -> RawFd {
        todo!()
    }
}

impl<'a, T: 'a> ArrayMap<'a, T> {
    pub fn new() -> ArrayMap<'a, T> {
        unimplemented!()
    }
}

impl<'a, T: 'a> RWMap<T> for ArrayMap<'a, T> {
    fn read(&self) -> Result<T, Box<dyn Error>> {
        unimplemented!()
    }

    fn write(&self) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}

impl<'a, T: 'a> ProgramMap for ArrayMap<'a, T> {
    fn load(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn unload(&self) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn get_fd(&self) -> RawFd {
        todo!()
    }
}

impl Drop for PerfMap {
    fn drop(&mut self) {
        todo!()
    }
}

impl<'a, T: 'a> Drop for ArrayMap<'a, T> {
    fn drop(&mut self) {
        todo!()
    }
}
