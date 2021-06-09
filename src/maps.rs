use std::marker::PhantomData;
use std::os::raw::{c_long, c_uchar, c_uint, c_ulong, c_ushort};
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
use std::slice;
use std::sync::atomic;
use std::sync::atomic::{AtomicPtr, Ordering};

use nix::errno::errno;

use crate::bpf::MapConfig;
use crate::error::OxidebpfError;
use crate::fmt;
use crate::perf::constant::perf_event_type;
use crate::perf::syscall::{perf_event_ioc_disable, perf_event_ioc_enable};
use crate::perf::PerfEventAttr;
use std::fmt::{Debug, Formatter};

#[repr(C)]
#[derive(Clone, Copy)]
struct PerfEventHeader {
    type_: c_uint,
    misc: c_ushort,
    size: c_ushort,
}
#[repr(C)]
pub struct PerfEventLostSamples {
    header: PerfEventHeader,
    pub id: u64,
    pub count: u64,
}

#[repr(C)]
pub struct PerfEventSample {
    header: PerfEventHeader,
    pub size: u32,
    pub data: Vec<u8>,
}

pub(crate) fn process_cpu_string(cpu_string: String) -> Result<Vec<i32>, OxidebpfError> {
    let mut cpus = Vec::<i32>::new();
    let cpu_string = cpu_string.trim();
    for sublist in cpu_string.split(',').into_iter() {
        if sublist.contains('-') {
            let pair: Vec<&str> = sublist.split('-').collect();
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

            (from..=to).into_iter().for_each(|i| cpus.push(i))
        } else {
            cpus.push(
                sublist
                    .trim()
                    .parse::<i32>()
                    .map_err(|_| OxidebpfError::NumberParserError)?,
            );
        }
    }

    Ok(cpus)
}

pub(crate) fn get_cpus() -> Result<Vec<i32>, OxidebpfError> {
    let cpu_string = String::from_utf8(
        std::fs::read("/sys/devices/system/cpu/online").map_err(|_| OxidebpfError::FileIOError)?,
    )
    .map_err(|_| OxidebpfError::Utf8StringConversionError)?;
    process_cpu_string(cpu_string)
}

pub(crate) enum PerfEvent<'a> {
    Sample(Box<PerfEventSample>),
    Lost(&'a PerfEventLostSamples),
}

impl Debug for PerfEvent<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PerfEvent::Sample(s) => {
                    format!("SAMPLE: {}", s.size)
                }
                PerfEvent::Lost(l) => {
                    format!("LOST: {}", l.count)
                }
            }
        )
    }
}

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

impl Debug for PerfMemCapabilitiesBitfield {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "debug not implemented")
    }
}

#[repr(C)]
#[derive(Debug)]
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
    pub(crate) name: String,
    base_ptr: AtomicPtr<PerfMem>,
    page_count: usize,
    page_size: usize,
    mmap_size: usize,
    cpuid: i32,
    pub(crate) ev_fd: RawFd,
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
    map_config_size: usize,
    loaded: bool,
}

pub trait RWMap<T> {
    fn read(&self) -> Result<T, OxidebpfError>;
    fn write(&self) -> Result<(), OxidebpfError>;
}

pub trait PerCpu {
    fn cpuid(&self) -> i32;
}

impl PerfMap {
    // we want cpuid and give back a channel to read from
    pub fn new_group(
        map_name: &str,
        event_attr: PerfEventAttr,
        event_buffer_size: usize,
    ) -> Result<Vec<PerfMap>, OxidebpfError> {
        let page_size = match unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } {
            size if size < 0 => {
                return Err(OxidebpfError::LinuxError(nix::errno::from_i32(errno())));
            }
            size if size == 0 => {
                return Err(OxidebpfError::BadPageSize);
            }
            size if size > 0 => size as usize,
            _ => return Err(OxidebpfError::BadPageSize),
        };
        let page_count = (event_buffer_size as f64 / page_size as f64).ceil() as usize;
        if page_count == 0 {
            return Err(OxidebpfError::BadPageCount);
        }
        let mmap_size = page_size * (page_count + 1);

        let mut loaded_perfmaps = Vec::<PerfMap>::new();
        for cpuid in get_cpus()?.iter() {
            let fd: RawFd = crate::perf::syscall::perf_event_open(&event_attr, -1, *cpuid, -1, 0)?;
            let base_ptr: *mut _;
            base_ptr = unsafe {
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
                let mmap_errno = nix::errno::from_i32(errno());
                unsafe {
                    if libc::close(fd) < 0 {
                        return Err(OxidebpfError::MultipleErrors(vec![
                            OxidebpfError::LinuxError(mmap_errno),
                            OxidebpfError::LinuxError(nix::errno::from_i32(errno())),
                        ]));
                    }
                };
                return Err(OxidebpfError::LinuxError(mmap_errno));
            }
            perf_event_ioc_enable(fd)?;
            loaded_perfmaps.push(PerfMap {
                name: map_name.to_string(),
                base_ptr: AtomicPtr::new(base_ptr as *mut PerfMem),
                page_count,
                page_size,
                mmap_size,
                cpuid: *cpuid,
                ev_fd: fd,
                ev_name: "".to_string(),
            });
        }
        Ok(loaded_perfmaps)
    }

    pub(crate) fn read<'a>(&self) -> Result<Option<PerfEvent<'a>>, OxidebpfError> {
        let header = self.base_ptr.load(Ordering::SeqCst);
        let raw_size = (self.page_count * self.page_size) as u64;
        let base: *const u8;
        let data_head: u64;
        let data_tail: u64;
        let event: *const PerfEventHeader;
        let start: usize;
        let end: usize;
        unsafe {
            base = (header as *const u8).add(self.page_size);
            data_head = (*header).data_head;
            data_tail = (*header).data_tail;
            start = (data_tail % raw_size) as usize;
            event = base.add(start) as *const PerfEventHeader;
            end = ((data_tail + (*event).size as u64) % raw_size) as usize;
        }
        if data_head == data_tail {
            return Err(OxidebpfError::NoPerfData);
        }

        let mut buf = Vec::<u8>::new();

        unsafe {
            if end < start {
                let len = (raw_size as usize - start) as usize;
                let ptr = base.add(start);
                buf.extend_from_slice(slice::from_raw_parts(ptr, len));

                let len = (*event).size as usize - len;
                let ptr = base;
                buf.extend_from_slice(slice::from_raw_parts(ptr, len));
            } else {
                let ptr = base.add(start);
                let len = (*event).size as usize;
                buf.extend_from_slice(slice::from_raw_parts(ptr, len));
            }

            atomic::fence(Ordering::SeqCst);
            (*header).data_tail += (*event).size as u64;

            match (*event).type_ {
                perf_event_type::PERF_RECORD_SAMPLE => {
                    let header_bytes: Vec<u8> = buf
                        .drain(..std::mem::size_of::<PerfEventHeader>())
                        .collect();
                    let len: Vec<u8> = buf.drain(..std::mem::size_of::<u32>()).collect();
                    let data: Vec<u8> = buf.drain(..).collect();
                    let (_, header, _) = header_bytes.align_to::<PerfEventHeader>();
                    let (_, size, _) = len.align_to::<u32>();
                    if header.len() != 1 {
                        return Err(OxidebpfError::BadPerfSample);
                    }
                    if size.len() != 1 {
                        return Err(OxidebpfError::BadPerfSample);
                    }
                    let header = *header.get(0).ok_or(OxidebpfError::BadPerfSample)?;
                    let size = *size.get(0).ok_or(OxidebpfError::BadPerfSample)?;
                    let sample = Box::new(PerfEventSample { header, size, data });
                    Ok(Some(PerfEvent::<'a>::Sample(sample)))
                }
                perf_event_type::PERF_RECORD_LOST => Ok(Some(PerfEvent::<'a>::Lost(
                    &*(buf.as_ptr() as *const PerfEventLostSamples),
                ))),
                _ => Ok(None),
            }
        }
    }
}

impl PerCpu for PerfMap {
    fn cpuid(&self) -> i32 {
        self.cpuid
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

impl Drop for PerfMap {
    fn drop(&mut self) {
        // if it doesn't work, we're gonna close it anyway so :shrug:
        #![allow(unused_must_use)]
        perf_event_ioc_disable(self.ev_fd);
        unsafe {
            libc::close(self.ev_fd);
        }
    }
}

impl<T> Drop for ArrayMap<T> {
    fn drop(&mut self) {
        todo!()
    }
}

#[cfg(test)]
mod map_tests {
    use crate::maps::process_cpu_string;

    #[test]
    fn test_cpu_formatter() {
        assert_eq!(vec![0], process_cpu_string("0".to_string()).unwrap());
        assert_eq!(
            vec![0, 1, 2],
            process_cpu_string("0-2".to_string()).unwrap()
        );
        assert_eq!(
            vec![0, 3, 4, 5, 8],
            process_cpu_string("0,3-5,8".to_string()).unwrap()
        );
    }
}
