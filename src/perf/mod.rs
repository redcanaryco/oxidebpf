use std::fmt::{Debug, Formatter};
use std::os::raw::{c_int, c_uint, c_ulong, c_ushort};

pub(crate) mod constant;
pub(crate) mod syscall;

#[repr(C)]
pub(crate) union PerfSample {
    pub(crate) sample_period: c_ulong,
    pub(crate) sample_freq: c_ulong,
}

impl Debug for PerfSample {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = unsafe { self.sample_freq };
        write!(f, "PerfSample: {}", value)
    }
}

impl Default for PerfSample {
    fn default() -> Self {
        Self {
            sample_period: 0u64,
        }
    }
}

#[repr(C)]
pub(crate) union PerfWakeup {
    pub(crate) wakeup_events: c_uint,
    pub(crate) wakeup_watermark: c_uint,
}

impl Debug for PerfWakeup {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = unsafe { self.wakeup_watermark };
        write!(f, "PerfWakeup: {}", value)
    }
}

impl Default for PerfWakeup {
    fn default() -> Self {
        Self {
            wakeup_events: 0u32,
        }
    }
}

#[repr(align(8), C)]
pub(crate) union PerfBpAddr {
    pub(crate) bp_addr: c_ulong,
    pub(crate) kprobe_func: c_ulong,
    pub(crate) uprobe_path: c_ulong,
    pub(crate) config1: c_ulong,
}

impl Debug for PerfBpAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = unsafe { self.bp_addr };
        write!(f, "PerfBpAddr: {}", value)
    }
}

impl Default for PerfBpAddr {
    fn default() -> Self {
        Self { bp_addr: 0u64 }
    }
}

#[repr(align(8), C)]
pub(crate) union PerfBpLen {
    pub(crate) bp_len: c_ulong,
    pub(crate) kprobe_addr: c_ulong,
    pub(crate) probe_offset: c_ulong,
    pub(crate) config2: c_ulong,
}

impl Debug for PerfBpLen {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = unsafe { self.bp_len };
        write!(f, "PerfBpLen: {}", value)
    }
}

impl Default for PerfBpLen {
    fn default() -> Self {
        Self { bp_len: 0u64 }
    }
}

#[repr(align(8), C)]
#[derive(Debug)]
pub struct PerfEventAttr {
    pub(crate) p_type: c_uint,
    pub(crate) size: c_uint,
    pub(crate) config: c_ulong,
    pub(crate) sample_union: PerfSample,
    pub(crate) sample_type: c_ulong,
    pub(crate) read_format: c_ulong,
    pub(crate) flags: c_ulong,
    pub(crate) wakeup_union: PerfWakeup,
    pub(crate) bp_type: c_uint,
    pub(crate) bp_addr_union: PerfBpAddr,
    pub(crate) bp_len_union: PerfBpLen,
    pub(crate) branch_sample_type: c_ulong, // enum perf_branch_sample_type
    pub(crate) sample_regs_user: c_ulong,
    pub(crate) sample_stack_user: c_uint,
    pub(crate) clockid: c_int,
    pub(crate) sample_regs_intr: c_ulong,
    pub(crate) aux_watermark: c_uint,
    pub(crate) sample_max_stack: c_ushort,
    pub(crate) __reserved_2: c_ushort,
    pub(crate) aux_sample_size: c_uint,
    pub(crate) __reserved_3: c_uint,
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self {
            p_type: 0,
            size: std::mem::size_of::<PerfEventAttr>() as u32,
            config: 0,
            sample_union: Default::default(),
            sample_type: 0,
            read_format: 0,
            flags: 0,
            wakeup_union: Default::default(),
            bp_type: 0,
            bp_addr_union: Default::default(),
            bp_len_union: Default::default(),
            branch_sample_type: 0,
            sample_regs_user: 0,
            sample_stack_user: 0,
            clockid: 0,
            sample_regs_intr: 0,
            aux_watermark: 0,
            sample_max_stack: 0,
            __reserved_2: 0,
            aux_sample_size: 0,
            __reserved_3: 0,
        }
    }
}
