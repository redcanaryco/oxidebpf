use crate::bpf::syscall::perf_event_ioc_enable;
use crate::bpf::{MapConfig, PerfEventAttr};
use crate::error::OxidebpfError;
use nix::errno::errno;
use std::borrow::Borrow;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::raw::{c_long, c_uchar, c_uint, c_ulong, c_ushort};
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
use std::sync::atomic::AtomicPtr;

fn get_cpus() -> Result<Vec<i32>, OxidebpfError> {
    let cpu_string = String::from_utf8(
        std::fs::read("/sys/devices/system/cpu/online").map_err(|_| OxidebpfError::FileIOError)?,
    )
    .map_err(|_| OxidebpfError::Utf8StringConversionError)?;
    let mut cpus = Vec::<i32>::new();
    for sublist in cpu_string.split(",").into_iter() {
        let pair: Vec<&str> = sublist.split("-").collect();
        if pair.len() != 2 {
            return Err(OxidebpfError::CpuOnlineFormatError);
        }
        let from = pair
            .get(0)
            .ok_or(OxidebpfError::CpuOnlineFormatError)?
            .parse::<i32>()
            .map_err(|_| OxidebpfError::CpuOnlineFormatError)?;
        let to = pair
            .get(1)
            .ok_or(OxidebpfError::CpuOnlineFormatError)?
            .parse::<i32>()
            .map_err(|_| OxidebpfError::CpuOnlineFormatError)?;
        (from..to).into_iter().for_each(|i| cpus.push(i))
    }
    Ok(cpus)
}

pub struct EventData {
    pub data: Vec<u8>,
}

pub(crate) enum Event {
    Some(EventData),
    Lost,
}

// #[repr(C)]
// #[derive(Copy, Clone)]
// pub union perf_event_mmap_page__bindgen_ty_1 {
//     pub capabilities: __u64,
//     pub __bindgen_anon_1: perf_event_mmap_page__bindgen_ty_1__bindgen_ty_1,
//     _bindgen_union_align: u64,
// }
// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct perf_event_mmap_page__bindgen_ty_1__bindgen_ty_1 {
//     pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize], u64>,
//     pub __bindgen_align: [u64; 0usize],
// }

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct PerfMemBitfield {
    field: c_ulong,
}

#[repr(align(8), C)]
union PerfMemCapabilitiesBitfield {
    capabilities: c_ulong,
    bitfield: PerfMemBitfield,
}

#[repr(C)]
struct PerfMem {
    version: c_uint,
    compat_version: c_uint,
    lock: c_uint,
    index: c_uint,
    offset: c_long,
    time_enabled: c_ulong,
    time_running: c_ulong,
    capabilities: PerfMemCapabilitiesBitfield,
    pmc_width: c_ushort,
    time_shift: c_ushort,
    time_mult: c_uint,
    time_offset: c_ulong,
    time_zero: c_ulong,
    size: c_uint,
    reserved_1: c_uint,
    time_cycles: c_ulong,
    time_mask: c_ulong,
    __reserved: [c_uchar; 928usize],
    data_head: c_ulong,
    data_tail: c_ulong,
    data_offset: c_ulong,
    data_size: c_ulong,
    aux_head: c_ulong,
    aux_tail: c_ulong,
    aux_offset: c_ulong,
    aux_size: c_ulong,
}

pub struct PerfMap {
    name: String,
    base_ptr: AtomicPtr<PerfMem>,
    page_count: usize,
    mmap_size: usize,
    ev_fd: RawFd,
    ev_name: String,
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
    pub fn new_group(
        map_name: &String,
        event_attr: PerfEventAttr,
        event_buffer_size: usize,
    ) -> Result<Vec<PerfMap>, OxidebpfError> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
        if page_size < 0 {
            return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
        } else if page_size == 0 {
            return Err(OxidebpfError::BadPageSize);
        }
        let page_size = page_size as usize;
        let page_count = event_buffer_size / page_size;
        let mmap_size = page_size * (page_count + 1);

        let mut loaded_perfmaps = Vec::<PerfMap>::new();
        for cpuid in get_cpus()?.iter() {
            // TODO: fallback on debugfs
            let fd: RawFd = crate::bpf::syscall::perf_event_open(&event_attr, -1, *cpuid, -1, 0)?;
            let base_ptr = unsafe {
                libc::mmap(
                    null_mut(),
                    mmap_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            if base_ptr == libc::MAP_FAILED {
                return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
            }
            perf_event_ioc_enable(fd)?;
            loaded_perfmaps.push(PerfMap {
                name: map_name.clone(),
                base_ptr: AtomicPtr::new(base_ptr as *mut PerfMem),
                page_count: page_count,
                mmap_size: mmap_size,
                ev_fd: fd,
                ev_name: "".to_string(),
            });
        }
        Ok(loaded_perfmaps)
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
