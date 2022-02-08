pub(crate) mod perf_map_poller;

use std::{
    fmt::{Debug, Display, Formatter},
    iter::FusedIterator,
    os::{
        raw::{c_long, c_uchar, c_uint, c_ulong, c_ushort},
        unix::io::RawFd,
    },
    ptr::null_mut,
    slice,
    sync::atomic::{self, AtomicPtr, Ordering},
};

use crate::{
    bpf::{
        constant::bpf_map_type::{self, BPF_MAP_TYPE_PROG_ARRAY},
        syscall::{bpf_map_create, bpf_map_lookup_elem, bpf_map_update_elem},
        MapConfig,
    },
    cpu_info,
    error::OxidebpfError,
    perf::{
        constant::perf_event_type,
        syscall::{perf_event_ioc_disable, perf_event_ioc_enable},
        PerfEventAttr,
    },
    program_version::PerfBufferSize,
    LOGGER,
};

use nix::errno::errno;
use slog::info;

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
    size: u32,
    // array to data of len `size` stored as as char[1] because Rust's
    // DST and C's DST are are not FFI compatible. This needs to be a
    // char[] to avoid padding issues since chars are special in c
    // padding (in that they do not get pre-padded)
    data: [std::os::raw::c_char; 1],
}

#[derive(Debug)]
pub(crate) enum PerfEvent {
    Sample(Vec<u8>),
    Lost(u64),
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
    buffer_size: usize,
    page_size: usize,
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
        event_buffer_size: PerfBufferSize,
    ) -> Result<Vec<PerfMap>, OxidebpfError> {
        let page_size = page_size()?;
        let online_cpus = cpu_info::online()?;
        let buffer_size = match event_buffer_size {
            PerfBufferSize::PerCpu(size) => size,
            PerfBufferSize::Total(total) => total / online_cpus.len(),
        };
        let page_count = (buffer_size as f64 / page_size as f64).ceil() as usize;
        if page_count == 0 {
            info!(LOGGER.0, "PerfMap::new_group(); bad page count (0)");
            return Err(OxidebpfError::BadPageCount);
        }

        let page_count = lte_power_of_two(page_count);
        let buffer_size = page_count * page_size;
        // allocate an extra page for metadata
        let mmap_size = buffer_size + page_size;

        #[cfg(feature = "metrics")]
        {
            metrics::describe_histogram!("perfmap.buffer_unread_pct", metrics::Unit::Percent, "");
            let labels = [("map_name", map_name.to_owned())];

            metrics::gauge!(
                "perfmap.buffer_size_kb",
                buffer_size as f64 / 1024_f64,
                &labels
            );

            metrics::gauge!("perfmap.num_buffers", online_cpus.len() as f64, &labels);
        }

        online_cpus
            .into_iter()
            .map(|cpuid| {
                let fd: RawFd =
                    crate::perf::syscall::perf_event_open(&event_attr, -1, cpuid, -1, 0)?;
                let base_ptr = unsafe { create_raw_perf(fd, mmap_size) }?;

                perf_event_ioc_enable(fd)?;

                Ok(PerfMap {
                    name: map_name.to_owned(),
                    base_ptr: AtomicPtr::new(base_ptr),
                    buffer_size,
                    page_size,
                    cpuid,
                    ev_fd: fd,
                    ev_name: "".to_owned(),
                })
            })
            .collect()
    }

    /// Reads all available events
    ///
    /// Stops reading if it encounters an unexpected perf event.
    ///
    /// When the returned iterator is dropped it internally marks the
    /// data as "read" so the ebpf program can re-use that
    /// data. Because of this we should process the iterator fast as
    /// to free space for more events.
    ///
    /// # Safety
    ///
    /// This is only safe if a single iterator is running per perfmap.
    /// This function is marked as `&self` for easiness of use and
    /// because it is internal only but it probably should be `&mut
    /// self`. When the iterator is dropped it internally changes data
    /// in the mmap that the kernel manages (data_tail to be precise)
    /// to tell it what is the last bit we read so we shouldn't have
    /// multiple mutations at the same time.
    pub(crate) unsafe fn read_all(
        &self,
    ) -> impl Iterator<Item = Result<PerfEvent, OxidebpfError>> + '_ {
        PerfEventIterator::new(self)
    }
}

struct PerfEventIterator<'a> {
    // modified by iterator
    data_tail: u64,
    data_head: u64,
    errored: bool,
    copy_buf: Vec<u8>, // re-usable buffer to make ring joins be contiguous

    // calculated at creation
    mmap_size: usize,
    base: *const u8,
    metadata: *mut PerfMem,

    // gives us the lifetime we need to prevent the iterator outliving
    // the perfmap
    _marker: std::marker::PhantomData<&'a PerfMap>,
}

impl<'a> PerfEventIterator<'a> {
    fn new(map: &'a PerfMap) -> Self {
        // the first page is just metadata
        let metadata = map.base_ptr.load(Ordering::SeqCst);

        // second page onwards is where the data starts
        let base = unsafe { (metadata as *const u8).add(map.page_size) };

        // per the docs: "On SMP-capable platforms, after reading
        // the data_head value, user space should issue an rmb()"
        let data_head = unsafe { (*metadata).data_head };
        atomic::fence(std::sync::atomic::Ordering::Acquire);

        let data_tail = unsafe { (*metadata).data_tail };

        let mmap_size = map.buffer_size;

        #[cfg(feature = "metrics")]
        {
            let labels = [
                ("map_name", map.name.clone()),
                ("cpu", map.cpuid.to_string()),
            ];

            let used = (data_head - data_tail) % mmap_size as u64;
            let pct_used = used as f64 / (mmap_size as f64 / 100_f64);
            metrics::histogram!("perfmap.buffer_unread_pct", pct_used, &labels);
        }

        PerfEventIterator {
            data_tail,
            data_head,
            errored: false,
            copy_buf: vec![],
            mmap_size,
            base,
            metadata,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<'a> Iterator for PerfEventIterator<'a> {
    type Item = Result<PerfEvent, OxidebpfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data_head == self.data_tail || self.errored {
            return None;
        }

        let start_offset = (self.data_tail % self.mmap_size as u64) as usize;

        unsafe {
            let mut header = self.base.add(start_offset) as *const PerfEventHeader;
            let event_size = (*header).size as usize;
            let capacity_remaining = self.mmap_size - start_offset;

            if capacity_remaining < event_size {
                // clear old data and reserve just enough for our event
                self.copy_buf.clear();
                self.copy_buf.reserve_exact(event_size);

                // copy last remaining end bits of ring buffer
                self.copy_buf.extend_from_slice(slice::from_raw_parts(
                    header as *const u8,
                    capacity_remaining,
                ));

                // wrap around start to copy first initial bits
                self.copy_buf.extend_from_slice(slice::from_raw_parts(
                    self.base,
                    event_size - capacity_remaining,
                ));

                header = self.copy_buf.as_ptr() as *const PerfEventHeader;
            }

            let event = read_event(header);

            // only update the internal tail for now. We will update
            // the actual tail when dropping the iterator. It would be
            // safe to update the tail now though since the data is
            // copied. We could consider modifying the tail sooner if
            // we aren't sending events fast enough in the future.
            self.data_tail += event_size as u64;

            if event.is_err() {
                // stop iteration on errors but still propagate that
                // first error
                self.errored = true;
            }

            Some(event)
        }
    }
}

/// Reads either a sample or a lost event. Errors for anything else
///
/// Safety: it has to come from a valid PerfEventHeader and have
/// memory past the end of the header for the actual data of the event
unsafe fn read_event(event: *const PerfEventHeader) -> Result<PerfEvent, OxidebpfError> {
    match (*event).type_ {
        perf_event_type::PERF_RECORD_SAMPLE => {
            let sample = event as *const PerfEventSample;
            let size = (*sample).size;
            // data is saved as a char[1] but it is really a char[]
            // (dynamic) in the stack. Rust doesn't like thin pointers
            // to DSTs so we need to carefully get the pointer to the
            // array so we can then make a Rust slice out of it.
            let data = std::ptr::addr_of!((*sample).data) as *const u8;

            // copies the data over which is not stricly necessary but
            // avoids playing safety chess with std::mem::forget since
            // we do not want to accidentally drop the data owned by
            // the perf buffer
            let data = std::slice::from_raw_parts(data, size as usize).to_vec();

            Ok(PerfEvent::Sample(data))
        }
        perf_event_type::PERF_RECORD_LOST => {
            let sample = event as *const PerfEventLostSamples;
            Ok(PerfEvent::Lost((*sample).count))
        }
        unknown => Err(OxidebpfError::UnknownPerfEvent(unknown)),
    }
}

impl Drop for PerfEventIterator<'_> {
    fn drop(&mut self) {
        unsafe {
            atomic::fence(std::sync::atomic::Ordering::SeqCst);
            (*self.metadata).data_tail = self.data_tail;
        }
    }
}

impl<'a> FusedIterator for PerfEventIterator<'a> {}

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
            info!(
                LOGGER.0,
                "ArrayMap::read(); attempted to read unloaded array map {}", self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            info!(
                LOGGER.0,
                "ArrayMap::read(); attempted to read array map with negative fd {}", self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            info!(
                LOGGER.0,
                "ArrayMap::read(); attempted to read array map with incorrect size; gave {}; should be {}",
                std::mem::size_of::<T>(),
                self.base.map_config.value_size
            );
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
            info!(
                LOGGER.0,
                "ArrayMap::write(); attempted to write unloaded array map {}", self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            info!(
                LOGGER.0,
                "ArrayMap::write(); attempted to write array map with negative fd {}",
                self.base.name
            );
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
            info!(
                LOGGER.0,
                "BpfHashMap::read(); attempted to read unloaded bpf hash map {}", self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            info!(
                LOGGER.0,
                "BpfHashMap::read(); attempted to read bpf hash map with negative fd {}",
                self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            info!(
                LOGGER.0,
                "BpfHashMap::read(); attempted to read bpf hash map with incorrect value size; gave {}; should be {}",
                std::mem::size_of::<T>(),
                self.base.map_config.value_size
            );
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        if std::mem::size_of::<U>() as u32 != self.base.map_config.key_size {
            info!(
                LOGGER.0,
                "BpfHashMap::read(); attempted to read bpf hash map with incorrect key size; gave {}; should be {}",
                std::mem::size_of::<U>(),
                self.base.map_config.key_size
            );
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
            info!(
                LOGGER.0,
                "BpfHashMap::write(); attempted to write unloaded bpf hash map {}", self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }
        if self.base.fd < 0 {
            info!(
                LOGGER.0,
                "BpfHashMap::write(); attempted to write bpf hash map with negative fd {}",
                self.base.name
            );
            return Err(OxidebpfError::MapNotLoaded);
        }

        // Try and verify that size of the value type matches the size of the value field in the map
        if std::mem::size_of::<T>() as u32 != self.base.map_config.value_size {
            info!(
                LOGGER.0,
                "BpfHashMap::write(); attempted to write bpf hash map with incorrect value size; gave {}; should be {}",
                std::mem::size_of::<T>(),
                self.base.map_config.value_size
            );
            return Err(OxidebpfError::MapValueSizeMismatch);
        }
        if std::mem::size_of::<U>() as u32 != self.base.map_config.key_size {
            info!(
                LOGGER.0,
                "BpfHashMap::write(); attempted to write bpf hash map with incorrect key size; gave {}; should be {}",
                std::mem::size_of::<U>(),
                self.base.map_config.key_size
            );
            return Err(OxidebpfError::MapKeySizeMismatch);
        }
        bpf_map_update_elem(self.base.fd, key, value)
    }
}

impl Drop for PerfMap {
    fn drop(&mut self) {
        // if it doesn't work, we're gonna close it anyway so :shrug:
        let _ = perf_event_ioc_disable(self.ev_fd);
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

// returns a power of two that is equal or less than n
fn lte_power_of_two(n: usize) -> usize {
    if n.is_power_of_two() {
        return n;
    }

    match n.checked_next_power_of_two() {
        None => 1 << (usize::BITS - 1),
        Some(x) => x >> 1,
    }
}

fn page_size() -> Result<usize, OxidebpfError> {
    let raw_size = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };

    match raw_size.cmp(&0) {
        std::cmp::Ordering::Less => {
            let e = errno();
            info!(
                LOGGER.0,
                "PerfMap::new_group(); perfmap error, size < 0: {}; errno: {}", raw_size, e
            );
            Err(OxidebpfError::LinuxError(
                "perf map get PAGE_SIZE".to_string(),
                nix::errno::from_i32(e),
            ))
        }
        std::cmp::Ordering::Equal => {
            info!(
                LOGGER.0,
                "PerfMap::new_group(); perfmap error, bad page size (size == 0)"
            );
            Err(OxidebpfError::BadPageSize)
        }
        std::cmp::Ordering::Greater => Ok(raw_size as usize),
    }
}

/// Creates a new PerfMem for the given file descriptor.
///
/// On error it will attempt to close the file descriptor and report
/// if it failed to close it.
///
/// # Safety:
/// The fd must be valid and come from a perf_event_open syscall
unsafe fn create_raw_perf(fd: RawFd, mmap_size: usize) -> Result<*mut PerfMem, OxidebpfError> {
    let base_ptr = libc::mmap(
        null_mut(),
        mmap_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );

    if base_ptr == libc::MAP_FAILED {
        Err(handle_map_failed(fd, mmap_size))
    } else {
        Ok(base_ptr as *mut PerfMem)
    }
}

unsafe fn handle_map_failed(fd: RawFd, mmap_size: usize) -> OxidebpfError {
    let mmap_errno = nix::errno::from_i32(errno());
    if libc::close(fd) < 0 {
        let e = errno();
        info!(LOGGER.0, "PerfMap::new_group(); could not close mmap fd, multiple errors; mmap_errno: {}; errno: {}", mmap_errno, e);
        return OxidebpfError::MultipleErrors(vec![
            OxidebpfError::LinuxError(
                format!("perf_map => mmap(fd={},size={})", fd, mmap_size),
                mmap_errno,
            ),
            OxidebpfError::LinuxError(
                format!("perf_map cleanup => close({})", fd),
                nix::errno::from_i32(e),
            ),
        ]);
    }

    info!(
        LOGGER.0,
        "PerfMap::new_group(); mmap failed while creating perfmap: {:?}", mmap_errno
    );

    OxidebpfError::LinuxError(
        format!("per_event_open => mmap(fd={},size={})", fd, mmap_size),
        mmap_errno,
    )
}

#[cfg(test)]
mod map_tests {
    use crate::error::OxidebpfError;
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
        assert!(should_fail.is_err());
        match should_fail {
            Err(OxidebpfError::LinuxError(_, errno)) => {
                assert_eq!(errno, Errno::ENOENT)
            }
            _ => {
                panic!("invalid OxidebpfError: {:?}", should_fail);
            }
        }
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
        match should_fail {
            OxidebpfError::LinuxError(_, errno) => {
                assert_eq!(errno, Errno::E2BIG)
            }
            _ => {
                panic!("invalid OxidebpfError: {:?}", should_fail);
            }
        }
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
        assert!(should_fail.is_err());
        match should_fail {
            Err(OxidebpfError::LinuxError(_, errno)) => {
                assert_eq!(errno, Errno::ENOENT)
            }
            _ => {
                panic!("invalid OxidebpfError: {:?}", should_fail);
            }
        }
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
