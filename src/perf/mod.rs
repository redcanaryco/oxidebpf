use std::os::raw::{c_int, c_uint, c_ulong};

pub(crate) mod constant;
pub(crate) mod syscall;

#[repr(C)]
pub(crate) union PerfSample {
    pub(crate) sample_period: c_ulong,
    pub(crate) sample_freq: c_ulong,
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

impl Default for PerfWakeup {
    fn default() -> Self {
        Self {
            wakeup_events: 0u32,
        }
    }
}

#[repr(C)]
pub(crate) union PerfBpAddr {
    pub(crate) bp_addr: c_ulong,
    pub(crate) config1: c_ulong,
}

impl Default for PerfBpAddr {
    fn default() -> Self {
        Self { bp_addr: 0u64 }
    }
}

#[repr(C)]
pub(crate) union PerfBpLen {
    pub(crate) bp_len: c_ulong,
    pub(crate) config2: c_ulong,
}

impl Default for PerfBpLen {
    fn default() -> Self {
        Self { bp_len: 0u64 }
    }
}

#[repr(C)]
#[derive(Default)]
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
    pub(crate) __reserved_2: c_uint, // align to __u64
}
