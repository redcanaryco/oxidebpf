use crate::bpf::MapConfig;
use crate::error::OxidebpfError;
use std::marker::PhantomData;
use std::os::unix::io::RawFd;

pub struct EventData {
    pub data: Vec<u8>,
}

pub(crate) enum Event {
    Some(EventData),
    Lost,
}
pub struct PerfMap {
    // TODO: perfmap functions
    name: String,
    ev_fds: Vec<RawFd>,
    ev_names: Vec<String>,
}

pub struct ArrayMap<T> {
    // TODO: read/write functions
    base: Map,
    _t: PhantomData<T>,
}

pub struct Map {
    name: String,
    fd: RawFd,
    map_config: MapConfig,
    loaded: bool,
}

pub trait ProgramMap {
    fn load(&mut self) -> Result<(), OxidebpfError>;
    fn unload(&mut self) -> Result<(), OxidebpfError>;
    fn get_fd(&self) -> Result<RawFd, OxidebpfError>; // if we don't (need to) track attachpoints this doesn't need to be exposed
}

pub trait RWMap<T> {
    fn read(&self) -> Result<T, OxidebpfError>;
    fn write(&self) -> Result<(), OxidebpfError>;
}

pub trait PerCpu {
    // What other per-cpu maps are there that we may want to use?
    fn cpuid(&self) -> u32;
}

impl PerfMap {
    // we want cpuid and give back a channel to read from
    pub fn new() -> Result<PerfMap, OxidebpfError> {
        // new is bind
        // open_perf_event to get fd
        // set up stuff to read from
        Ok(PerfMap {
            name: "".to_string(),
            ev_fds: vec![],
            ev_names: vec![],
        })
    }

    pub(crate) fn read(&self) -> Option<Event> {
        // TODO: every event out of the channel is some Event::Lost() or Event::Sample() of raw
        None
    }
}

impl PerCpu for PerfMap {
    fn cpuid(&self) -> u32 {
        todo!()
    }
}

impl ProgramMap for PerfMap {
    fn load(&mut self) -> Result<(), OxidebpfError> {
        todo!()
    }

    fn unload(&mut self) -> Result<(), OxidebpfError> {
        todo!()
    }

    fn get_fd(&self) -> Result<RawFd, OxidebpfError> {
        todo!()
    }
}

impl<T> ArrayMap<T> {
    pub fn new() -> ArrayMap<T> {
        unimplemented!()
    }
}

impl<T> RWMap<T> for ArrayMap<T> {
    fn read(&self) -> Result<T, OxidebpfError> {
        unimplemented!()
    }

    fn write(&self) -> Result<(), OxidebpfError> {
        unimplemented!()
    }
}

impl<T> ProgramMap for ArrayMap<T> {
    fn load(&mut self) -> Result<(), OxidebpfError> {
        todo!()
    }

    fn unload(&mut self) -> Result<(), OxidebpfError> {
        todo!()
    }

    fn get_fd(&self) -> Result<RawFd, OxidebpfError> {
        todo!()
    }
}

impl ProgramMap for Map {
    fn load(&mut self) -> Result<(), OxidebpfError> {
        let fd = crate::bpf::syscall::bpf_map_create_with_config(self.map_config)?;
        self.fd = fd;
        self.loaded = true;
        Ok(())
    }
    fn unload(&mut self) -> std::result::Result<(), OxidebpfError> {
        // TODO: close FD
        self.loaded = false;
        Ok(())
    }
    fn get_fd(&self) -> Result<RawFd, OxidebpfError> {
        if self.loaded {
            Ok(self.fd)
        } else {
            Err(OxidebpfError::MapNotLoaded)
        }
    }
}

impl Drop for PerfMap {
    fn drop(&mut self) {
        todo!()
    }
}

impl<T> Drop for ArrayMap<T> {
    fn drop(&mut self) {
        todo!()
    }
}
