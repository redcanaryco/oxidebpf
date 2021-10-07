use std::convert::TryInto;
use std::os::raw::{c_long, c_uchar, c_uint, c_ulong, c_ushort};
use std::os::unix::io::RawFd;
use std::ptr::null_mut;
use std::slice;
use std::sync::atomic;
use std::sync::atomic::{AtomicPtr, Ordering};

use nix::errno::errno;

use crate::bpf::constant::bpf_map_type;
use crate::bpf::constant::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY;
use crate::bpf::syscall::{bpf_map_create, bpf_map_lookup_elem, bpf_map_update_elem};
use crate::bpf::MapConfig;
use crate::error::OxidebpfError;
use crate::perf::constant::perf_event_type;
use crate::perf::syscall::{perf_event_ioc_disable, perf_event_ioc_enable};
use crate::perf::PerfEventAttr;
use slog::info;
use std::fmt::{Debug, Display, Formatter};

use crate::LOGGER;

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
    let mut cpus = vec![];

    for sublist in cpu_string.trim().split(',') {
        if sublist.contains('-') {
            let pair: Vec<&str> = sublist.split('-').collect();
            if pair.len() != 2 {
                return Err(OxidebpfError::CpuOnlineFormatError);
            }

            // we checked the length above so indexing is OK
            let from: i32 = pair[0]
                .parse()
                .map_err(|_| OxidebpfError::CpuOnlineFormatError)?;
            let to: i32 = pair[1]
                .parse()
                .map_err(|_| OxidebpfError::CpuOnlineFormatError)?;

            cpus.extend(from..=to)
        } else {
            cpus.push(
                sublist
                    .trim()
                    .parse()
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
    Sample(PerfEventSample),
    Lost(&'a PerfEventLostSamples),
}

impl Debug for PerfEvent<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

#[derive(Clone, Debug)]
pub(crate) struct ProgMap {
    pub base: Map,
}

#[derive(Clone, Debug)]
pub struct ArrayMap {
    pub base: Map,
}

#[derive(Clone, Debug)]
pub struct BpfHashMap {
    pub base: Map,
}

#[derive(Debug)]
pub struct Map {
    pub name: String,       // The name of the map
    fd: RawFd,              // The file descriptor that represents the map
    map_config: MapConfig,  // The first struct in the bpf_attr union
    map_config_size: usize, // The size of the map_config field in bytes
    loaded: bool,           // Whether or not the map has been loaded
}

impl Clone for Map {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            fd: unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 3) },
            map_config: self.map_config,
            map_config_size: self.map_config_size,
            loaded: self.loaded,
        }
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// This trait specifies a map that can be read from or written to (e.g., array types).
pub trait RWMap<T, U> {
    /// # Safety
    ///
    /// This function should only be called when `std::mem::size_of::<T>()` matches
    /// the value in the map being read from and when `std::mem::size_of::<U>()`
    /// matches the key.
    unsafe fn read(&self, key: U) -> Result<T, OxidebpfError>;

    /// # Safety
    ///
    /// This function should only be called when `std::mem::size_of::<T>()` matches
    /// the value in the map being written to and when `std::mem::size_of::<U>()`
    /// matches the key.
    unsafe fn write(&self, key: U, value: T) -> Result<(), OxidebpfError>;
}

pub trait PerCpu {
    fn cpuid(&self) -> i32;
}

impl ProgMap {
    pub(crate) fn new(map_name: &str, max_entries: u32) -> Result<Self, OxidebpfError> {
        let fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, 4u32, 4u32, max_entries)?;
        let map = Map {
            name: map_name.to_string(),
            fd,
            map_config: MapConfig::new(bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY, 4, 4, max_entries),
            map_config_size: std::mem::size_of::<MapConfig>(),
            loaded: true,
        };
        Ok(ProgMap { base: map })
    }

    // TODO: these functions are a good candidate for a trait
    pub(crate) fn set_fd(&mut self, fd: RawFd) {
        self.base.fd = fd;
    }

    pub(crate) fn get_fd(&self) -> &RawFd {
        &self.base.fd
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.base.loaded
    }
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
                let e = errno();
                info!(LOGGER, "perfmap error, size < 0: {}; errno: {}", size, e);
                return Err(OxidebpfError::LinuxError(nix::errno::from_i32(e)));
            }
            size if size == 0 => {
                info!(LOGGER, "perfmap error, bad page size (size == 0)");
                return Err(OxidebpfError::BadPageSize);
            }
            size if size > 0 => size as usize,
            size => {
                info!(LOGGER, "perfmap error, impossible page size: {}", size);
                return Err(OxidebpfError::BadPageSize);
            }
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
                        let e = errno();
                        info!(
                            LOGGER,
                            "could not close mmap fd, multiple errors; mmap_errno: {}; errno: {}",
                            mmap_errno,
                            e
                        );
                        return Err(OxidebpfError::MultipleErrors(vec![
                            OxidebpfError::LinuxError(mmap_errno),
                            OxidebpfError::LinuxError(nix::errno::from_i32(e)),
                        ]));
                    }
                };
                info!(
                    LOGGER,
                    "mmap failed while creating perfmap: {:?}", mmap_errno
                );
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
                let len = raw_size as usize - start;
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
                    use std::mem::size_of;

                    let header = {
                        let header_bytes: [u8; size_of::<PerfEventHeader>()] = buf
                            [..size_of::<PerfEventHeader>()]
                            .try_into()
                            .map_err(|_| OxidebpfError::BadPerfSample)?;
                        std::ptr::read(header_bytes.as_ptr() as *const _)
                    };

                    let size = {
                        let size_bytes: [u8; size_of::<u32>()] = buf[size_of::<PerfEventHeader>()
                            ..(size_of::<u32>() + size_of::<PerfEventHeader>())]
                            .try_into()
                            .map_err(|_| OxidebpfError::BadPerfSample)?;
                        u32::from_ne_bytes(size_bytes)
                    };

                    let data = {
                        // drain the header + len fields; the rest is the data
                        buf.drain(
                            ..(std::mem::size_of::<PerfEventHeader>() + std::mem::size_of::<u32>()),
                        )
                        // might be unnecesary but I like this being explicit
                        .for_each(|_| {});

                        buf
                    };

                    let sample = PerfEventSample { header, size, data };
                    Ok(Some(PerfEvent::Sample(sample)))
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

impl BpfHashMap {
    /// Create a new BpfHashMap
    ///
    /// Calling new will create a new BPF_MAP_TYPE_HASH map. It stores some meta data
    /// to track it. The array map supports read and write operations to access the
    /// members of the map
    ///
    /// # Safety
    ///
    /// The `value_size` and `key_size` you pass in needs to match exactly with the size of the struct/type
    /// used by any other BPF program that might be using this map. Any `T` or `U` you use in subsequent
    /// `read()` and `write()` calls needs to match exactly (e.g., with `#[repr(C)]`) with the struct/type
    /// used by the BPF program as well. Additionally, `std::mem::size_of::<T>()` must match the given
    /// `value_size` here exactly and `std::mem::size_of::<U>() for the key`. If this conditions are not met,
    /// the `BpfHashMap` behavior is undefined.
    ///
    /// # Examples
    /// ```
    /// use oxidebpf::BpfHashMap;
    /// let map: BpfHashMap = unsafe {BpfHashMap::new(
    ///    "mymap",
    ///    std::mem::size_of::<u64>() as u32,
    ///    std::mem::size_of::<u64>() as u32,
    ///    1024,
    /// ).expect("Failed to create map") };
    /// ```
    pub unsafe fn new(
        map_name: &str,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<BpfHashMap, OxidebpfError> {
        // Manpages say that key size must be 4 bytes for BPF_MAP_TYPE_ARRAY
        let fd = bpf_map_create(
            bpf_map_type::BPF_MAP_TYPE_HASH,
            key_size as c_uint,
            value_size as c_uint,
            max_entries,
        )?;
        let map = Map {
            name: map_name.to_string(),
            fd,
            map_config: MapConfig::new(
                bpf_map_type::BPF_MAP_TYPE_HASH,
                key_size,
                value_size,
                max_entries,
            ),
            map_config_size: std::mem::size_of::<MapConfig>(),
            loaded: true,
        };
        Ok(BpfHashMap { base: map })
    }

    pub(crate) fn set_fd(&mut self, fd: RawFd) {
        self.base.fd = fd;
    }

    pub(crate) fn get_fd(&self) -> &RawFd {
        &self.base.fd
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.base.loaded
    }
}

impl Display for BpfHashMap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Name: {}, loaded: {}", self.base.name, self.base.loaded)
    }
}

impl ArrayMap {
    /// Create a new ArrayMap
    ///
    /// Calling new will create a new BPF_MAP_TYPE_ARRAY map. It stores some meta data
    /// to track it. The array map supports read and write operations to access the
    /// members of the map
    ///
    /// # Safety
    ///
    /// The `value_size` you pass in needs to match exactly with the size of the struct/type
    /// used by any other BPF program that might be using this map. Any `T` you use in subsequent
    /// `read()` and `write()` calls needs to match exactly (e.g., with `#[repr(C)]`) with
    /// the struct/type used by the BPF program as well. Additionally, `std::mem::size_of::<T>()`
    /// must match the given `value_size` here exactly. If this conditions are not met, the
    /// `ArrayMap` behavior is undefined.
    ///
    /// # Examples
    /// ```
    /// use oxidebpf::ArrayMap;
    /// let map: ArrayMap = unsafe {ArrayMap::new(
    ///    "mymap",
    ///    std::mem::size_of::<u64>() as u32,
    ///    1024,
    /// ).expect("Failed to create map") };
    /// ```
    pub unsafe fn new(
        map_name: &str,
        value_size: u32,
        max_entries: u32,
    ) -> Result<ArrayMap, OxidebpfError> {
        // Manpages say that key size must be 4 bytes for BPF_MAP_TYPE_ARRAY
        let fd = bpf_map_create(
            bpf_map_type::BPF_MAP_TYPE_ARRAY,
            4,
            value_size as c_uint,
            max_entries,
        )?;
        let map = Map {
            name: map_name.to_string(),
            fd,
            map_config: MapConfig::new(
                bpf_map_type::BPF_MAP_TYPE_ARRAY,
                4,
                value_size,
                max_entries,
            ),
            map_config_size: std::mem::size_of::<MapConfig>(),
            loaded: true,
        };
        Ok(ArrayMap { base: map })
    }

    pub(crate) fn set_fd(&mut self, fd: RawFd) {
        self.base.fd = fd;
    }

    pub(crate) fn get_fd(&self) -> &RawFd {
        &self.base.fd
    }

    pub(crate) fn is_loaded(&self) -> bool {
        self.base.loaded
    }
}

impl Display for ArrayMap {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Name: {}, loaded: {}", self.base.name, self.base.loaded)
    }
}

impl<T> RWMap<T, c_uint> for ArrayMap {
    /// Reads an index from a map of type BPF_MAP_TYPE_ARRAY
    ///
    /// Initiates a read from `key`. Read verifies that the map has been initialized.
    /// The value returned will be of the same type that was used when the ArrayMap
    /// was created
    ///
    /// NOTE: This method calls will read a certain amount of memory based on what the
    /// size of `T` is. Make sure that `T` matches the type of the value (e.g., with `#[repr(C)]`)
    /// that is being used in the map.
    ///
    /// # Example
    /// ```
    /// use oxidebpf::{ArrayMap, RWMap};
    ///
    /// // this is safe because we are reading and writing a u64, and the value_size we
    /// // pass into new() is a u64
    ///
    /// unsafe {
    ///     let map: ArrayMap = ArrayMap::new(
    ///        "mymap",
    ///        std::mem::size_of::<u64>() as u32,
    ///        1024,
    ///     ).expect("Failed to create map");
    ///     let _ = map.write(0, 12345u64);
    ///     assert_eq!(
    ///         12345u64,
    ///         unsafe { map.read(0).expect("Failed to read value from map") }
    ///     );
    /// }
    /// ```
    unsafe fn read(&self, key: c_uint) -> Result<T, OxidebpfError> {
        if !self.base.loaded {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        bpf_map_lookup_elem(self.base.fd, key)
    }

    /// Writes an index to and index of a map of type BPF_MAP_TYPE_ARRAY
    ///
    /// Initiates a write to `key` of `value`. The value needs to match the array
    /// type that was used when the map was created
    ///
    /// NOTE: This method calls will write a certain amount of memory based on what the
    /// size of `T` is. Make sure that `T` matches the type of the value (e.g., with `#[repr(C)]`)
    /// that is being used in the map.
    ///
    /// # Example
    /// ```
    /// use oxidebpf::{ArrayMap, RWMap};
    ///
    /// // this is safe because we are reading and writing a u64, and the value_size we
    /// // pass into new() is a u64
    ///
    /// unsafe {
    ///     let map: ArrayMap = ArrayMap::new(
    ///        "mymap",
    ///        std::mem::size_of::<u64>() as u32,
    ///        1024,
    ///     ).expect("Failed to create map");
    ///     let _ = map.write(0, 12345u64);
    ///     assert_eq!(
    ///         12345u64,
    ///         map.read(0).expect("Failed to read value from map")
    ///     );
    /// }
    /// ```
    unsafe fn write(&self, key: c_uint, value: T) -> Result<(), OxidebpfError> {
        if !self.base.loaded {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            return Err(OxidebpfError::MapNotLoaded);
        }

        // Try and verify that size of the value type matches the size of the value field in the map
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        bpf_map_update_elem(self.base.fd, key, value)
    }
}

impl<T, U> RWMap<T, U> for BpfHashMap {
    /// Reads an index from a map of type BPF_MAP_TYPE_HASH
    ///
    /// Initiates a read from `key`. Read verifies that the map has been initialized.
    /// The value returned will be of the same type that was used when the BpfHashMap
    /// was created
    ///
    /// NOTE: This method calls will read a certain amount of memory based on what the
    /// size of `T` and `U` is. Make sure that `T` and `U` matches the type of the value and key
    /// (e.g., with `#[repr(C)]`) that is being used in the map.
    ///
    /// # Example
    /// ```
    /// use oxidebpf::{BpfHashMap, RWMap};
    ///
    /// // this is safe because we are reading and writing a u64, and the value_size we
    /// // pass into new() is a u64
    ///
    /// unsafe {
    ///     let map: BpfHashMap = BpfHashMap::new(
    ///        "mymap",
    ///        std::mem::size_of::<u64>() as u32,
    ///        std::mem::size_of::<u64>() as u32,
    ///        1024,
    ///     ).expect("Failed to create map");
    ///     let _ = map.write(87654321u64, 12345u64);
    ///     assert_eq!(
    ///         12345u64,
    ///         unsafe { map.read(87654321u64).expect("Failed to read value from map") }
    ///     );
    /// }
    /// ```
    unsafe fn read(&self, key: U) -> Result<T, OxidebpfError> {
        if !self.base.loaded {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        if std::mem::size_of::<U>() as u32 != self.base.map_config.key_size {
            return Err(OxidebpfError::MapKeySizeMismatch);
        }
        bpf_map_lookup_elem(self.base.fd, key)
    }

    /// Writes an index to and index of a map of type BPF_MAP_TYPE_ARRAY
    ///
    /// Initiates a write to `key` of `value`. The value needs to match the array
    /// type that was used when the map was created
    ///
    /// NOTE: This method calls will write a certain amount of memory based on what the
    /// size of `T` is. Make sure that `T` matches the type of the value (e.g., with `#[repr(C)]`)
    /// that is being used in the map.
    ///
    /// # Example
    /// ```
    /// use oxidebpf::{BpfHashMap, RWMap};
    /// use std::process;
    ///
    /// // this is safe because we are reading and writing a u64, and the value_size we
    /// // pass into new() is a u64
    ///
    /// unsafe {
    ///     let map: BpfHashMap = BpfHashMap::new(
    ///        "mymap",
    ///        std::mem::size_of::<u32>() as u32,
    ///        std::mem::size_of::<u64>() as u32,
    ///        1024,
    ///     ).expect("Failed to create map");
    ///     let _ = map.write(process::id(), 12345u64);
    ///     assert_eq!(
    ///         12345u64,
    ///         map.read(process::id()).expect("Failed to read value from map")
    ///     );
    /// }
    /// ```
    unsafe fn write(&self, key: U, value: T) -> Result<(), OxidebpfError> {
        if !self.base.loaded {
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            return Err(OxidebpfError::MapNotLoaded);
        }

        // Try and verify that size of the value type matches the size of the value field in the map
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        if std::mem::size_of::<U>() as u32 != self.base.map_config.key_size {
            return Err(OxidebpfError::MapKeySizeMismatch);
        }
        bpf_map_update_elem(self.base.fd, key, value)
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

impl Drop for ArrayMap {
    fn drop(&mut self) {
        self.base.loaded = false;
    }
}

#[cfg(test)]
mod map_tests {
    use crate::error::OxidebpfError;
    use crate::maps::process_cpu_string;
    use crate::maps::RWMap;
    use crate::maps::{ArrayMap, BpfHashMap};
    use nix::errno::Errno;

    // Doing the rough equivalent of C's time(NULL);
    fn time_null() -> u64 {
        let start = std::time::SystemTime::now();
        let seed_time = start
            .duration_since(std::time::UNIX_EPOCH)
            .expect("All time is broken!!");
        seed_time.as_millis() as u64
    }

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

    // Test the normal behavior of the array map type
    //
    // This test simply writes to all the entries in the map and then tries to read
    // them back. If it successfully reads the values back from the map then it
    // is considered passing
    #[test]
    fn test_map_array() {
        let array_size: u64 = 100;
        let map: ArrayMap = unsafe {
            ArrayMap::new(
                "mymap",
                std::mem::size_of::<u64>() as u32,
                array_size as u32,
            )
            .expect("Failed to create new map")
        };

        // Give it some "randomness"
        let nums: Vec<u64> = (0..array_size)
            .map(|v| (v * time_null() + 71) % 128)
            .collect();

        // Write
        for (idx, num) in nums.iter().enumerate() {
            unsafe { map.write(idx as u32, *num).expect("could not write to map") };
        }
        for (idx, num) in nums.iter().enumerate() {
            assert_eq!(*num, unsafe {
                map.read(idx as u32).expect("Failed to read value from map")
            });
        }

        // Updates the entries and retrieves them again
        let nums: Vec<u64> = nums.iter().map(|v| (v * time_null() + 71) % 128).collect();
        for (idx, num) in nums.iter().enumerate() {
            unsafe { map.write(idx as u32, *num).expect("could not write to map") };
        }
        for (idx, num) in nums.iter().enumerate() {
            assert_eq!(*num, unsafe {
                map.read(idx as u32).expect("Failed to read value from map")
            });
        }
    }

    // Tests a trying to read an element from outside the bounds of the array
    #[test]
    fn test_map_array_bad_index() {
        let array_size: u64 = 10;
        let map: ArrayMap = unsafe {
            ArrayMap::new(
                "mymap",
                std::mem::size_of::<u64>() as u32,
                array_size as u32,
            )
            .expect("Failed to create new map")
        };

        // Give it some "randomness"
        let nums: Vec<u64> = (0..array_size)
            .map(|v| (v * time_null() + 71) % 128)
            .collect();

        for (idx, num) in nums.iter().enumerate() {
            unsafe { map.write(idx as u32, *num).expect("could not write to map") };
        }
        let should_fail: Result<u64, OxidebpfError> = unsafe { map.read(100) };
        assert_eq!(
            should_fail.err().unwrap(),
            OxidebpfError::LinuxError(Errno::ENOENT)
        );
    }

    // Test writing outside the size of the array
    #[test]
    fn test_map_array_bad_write_index() {
        let array_size: u64 = 10;
        let map: ArrayMap = unsafe {
            ArrayMap::new(
                "mymap",
                std::mem::size_of::<u64>() as u32,
                array_size as u32,
            )
            .expect("Failed to create new map")
        };

        // Give it some "randomness"
        let nums: Vec<u64> = (0..array_size)
            .map(|v| (v * time_null() + 71) % 128)
            .collect();

        for (idx, num) in nums.iter().enumerate() {
            unsafe { map.write(idx as u32, *num).expect("could not write to map") };
        }

        // Should return E2BIG
        let should_fail = unsafe { map.write(100, 12345u64).err().unwrap() };
        assert_eq!(should_fail, OxidebpfError::LinuxError(Errno::E2BIG));
    }

    // Test storing a more complex structure
    #[test]
    fn test_map_array_complex_structure() {
        // A made up structure for this test
        struct TestStructure {
            durp0: u64,
            durp1: String,
            durp2: f64,
            durp3: bool,
        }

        // Create the map and initialize a vector of TestStructure
        let array_size: u64 = 10;
        let map: ArrayMap = unsafe {
            ArrayMap::new(
                "mymap",
                std::mem::size_of::<u64>() as u32,
                array_size as u32,
            )
            .expect("Failed to create new map")
        };

        let data: Vec<TestStructure> = (0..array_size)
            .map(|v| TestStructure {
                durp0: v,
                durp1: format!("Durp {}", v),
                durp2: 0.1234,
                durp3: v % 2 == 0,
            })
            .collect();

        // Write the test structures to the map
        for (i, tmp) in data.iter().enumerate() {
            unsafe { map.write(i as u32, tmp).expect("could not write to map") };
        }

        // Read the test structures from the map and compare with originals
        for (i, item) in data.iter().enumerate() {
            let val: &TestStructure =
                unsafe { map.read(i as u32).expect("Failed to read value from array") };
            assert_eq!(val.durp0, item.durp0);
            assert_eq!(val.durp1, item.durp1);
            assert_eq!(val.durp2, item.durp2);
            assert_eq!(val.durp3, item.durp3);
        }
    }

    #[test]
    fn test_hash_map() {
        let array_size: u64 = 100;

        let map: BpfHashMap = unsafe {
            BpfHashMap::new(
                "mymap",
                std::mem::size_of::<u32>() as u32,
                std::mem::size_of::<u64>() as u32,
                1024,
            )
            .expect("Failed to create new map")
        };
        // Give it some "randomness"
        let nums: Vec<u64> = (0..array_size)
            .map(|v| (v * time_null() + 71) % 128)
            .collect();
        for num in nums.iter() {
            unsafe {
                let _ = map.write(std::process::id(), *num);
                let val: u64 = map
                    .read(std::process::id())
                    .expect("Failed to read value from hashmap");
                assert_eq!(val, *num);
            }
        }
    }

    #[test]
    fn test_hash_map_bad_index() {
        let map: BpfHashMap = unsafe {
            BpfHashMap::new(
                "mymap",
                std::mem::size_of::<u32>() as u32,
                std::mem::size_of::<u64>() as u32,
                1024,
            )
            .expect("Failed to create new map")
        };
        let _ = unsafe { map.write(1234, 1234) };
        let should_fail: Result<u64, OxidebpfError> = unsafe { map.read(4321) };
        assert_eq!(
            should_fail.err().unwrap(),
            OxidebpfError::LinuxError(Errno::ENOENT)
        );
    }

    #[test]
    fn test_hash_map_complex_key_value() {
        // A made up structure for this test
        #[derive(Clone, Copy)]
        struct TestStructure<'a> {
            durp0: u64,
            durp1: &'a str,
            durp2: f64,
            durp3: bool,
        }

        // Create the map and initialize a vector of TestStructure
        let array_size: u32 = 10;
        let map: BpfHashMap = unsafe {
            BpfHashMap::new(
                "mymap",
                std::mem::size_of::<u32>() as u32,
                std::mem::size_of::<TestStructure>() as u32,
                array_size as u32,
            )
            .expect("Failed to create new map")
        };

        let data: Vec<TestStructure> = (0..array_size)
            .map(|v| TestStructure {
                durp0: v as u64,
                durp1: "Durp",
                durp2: 0.1234,
                durp3: v % 2 == 0,
            })
            .collect();

        // Write the test structures to the map
        for (i, item) in data.iter().enumerate() {
            unsafe {
                map.write(std::process::id() + i as u32, *item)
                    .expect("could not write to map");
            }
            let val: TestStructure = unsafe {
                map.read(std::process::id() + i as u32)
                    .expect("Failed to read value from array")
            };
            assert_eq!(val.durp0, item.durp0);
            assert_eq!(val.durp1, item.durp1);
            assert_eq!(val.durp2, item.durp2);
            assert_eq!(val.durp3, item.durp3);
        }
    }
}
