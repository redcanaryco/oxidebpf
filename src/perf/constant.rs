#![allow(unused)]
use lazy_static::lazy_static;
use std::path::PathBuf;

lazy_static! {
    pub(crate) static ref PERF_PATH: PathBuf =
        PathBuf::from("/proc/sys/kernel/perf_event_paranoid");
    pub(crate) static ref PMU_KRETPROBE_FILE: PathBuf =
        PathBuf::from("/sys/bus/event_source/devices/kprobe/format/retprobe");
    pub(crate) static ref PMU_URETPROBE_FILE: PathBuf =
        PathBuf::from("/sys/bus/event_source/devices/uprobe/format/retprobe");
    pub(crate) static ref PMU_KTYPE_FILE: PathBuf =
        PathBuf::from("/sys/bus/event_source/devices/kprobe/type");
    pub(crate) static ref PMU_UTYPE_FILE: PathBuf =
        PathBuf::from("/sys/bus/event_source/devices/uprobe/type");
    pub(crate) static ref PMU_TTYPE_FILE: PathBuf =
        PathBuf::from("/sys/bus/event_source/devices/tracepoint/type");
}

pub(crate) mod perf_event_sample_format {
    pub const PERF_SAMPLE_IP: u32 = 1 << 0;
    pub const PERF_SAMPLE_TID: u32 = 1 << 1;
    pub const PERF_SAMPLE_TIME: u32 = 1 << 2;
    pub const PERF_SAMPLE_ADDR: u32 = 1 << 3;
    pub const PERF_SAMPLE_READ: u32 = 1 << 4;
    pub const PERF_SAMPLE_CALLCHAIN: u32 = 1 << 5;
    pub const PERF_SAMPLE_ID: u32 = 1 << 6;
    pub const PERF_SAMPLE_CPU: u32 = 1 << 7;
    pub const PERF_SAMPLE_PERIOD: u32 = 1 << 8;
    pub const PERF_SAMPLE_STREAM_ID: u32 = 1 << 9;
    pub const PERF_SAMPLE_RAW: u32 = 1 << 10;
    pub const PERF_SAMPLE_BRANCH_STACK: u32 = 1 << 11;
    pub const PERF_SAMPLE_REGS_USER: u32 = 1 << 12;
    pub const PERF_SAMPLE_STACK_USER: u32 = 1 << 13;
    pub const PERF_SAMPLE_WEIGHT: u32 = 1 << 14;
    pub const PERF_SAMPLE_DATA_SRC: u32 = 1 << 15;
    pub const PERF_SAMPLE_IDENTIFIER: u32 = 1 << 16;
    pub const PERF_SAMPLE_TRANSACTION: u32 = 1 << 17;
    pub const PERF_SAMPLE_REGS_INTR: u32 = 1 << 18;
    pub const PERF_SAMPLE_PHYS_ADDR: u32 = 1 << 19;
    pub const PERF_SAMPLE_AUX: u32 = 1 << 20;
    pub const PERF_SAMPLE_CGROUP: u32 = 1 << 21;
    pub const PERF_SAMPLE_DATA_PAGE_SIZE: u32 = 1 << 22;
    pub const PERF_SAMPLE_CODE_PAGE_SIZE: u32 = 1 << 23;
    pub const PERF_SAMPLE_WEIGHT_STRUCT: u32 = 1 << 24;
}

pub(crate) mod perf_type_id {
    pub const PERF_TYPE_HARDWARE: u32 = 0;
    pub const PERF_TYPE_SOFTWARE: u32 = 1;
    pub const PERF_TYPE_TRACEPOINT: u32 = 2;
    pub const PERF_TYPE_HW_CACHE: u32 = 3;
    pub const PERF_TYPE_RAW: u32 = 4;
    pub const PERF_TYPE_BREAKPOINT: u32 = 5;
}

pub(crate) mod perf_sw_ids {
    pub const PERF_COUNT_SW_CPU_CLOCK: u32 = 0;
    pub const PERF_COUNT_SW_TASK_CLOCK: u32 = 1;
    pub const PERF_COUNT_SW_PAGE_FAULTS: u32 = 2;
    pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u32 = 3;
    pub const PERF_COUNT_SW_CPU_MIGRATIONS: u32 = 4;
    pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u32 = 5;
    pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u32 = 6;
    pub const PERF_COUNT_SW_ALIGNMENT_FAULTS: u32 = 7;
    pub const PERF_COUNT_SW_EMULATION_FAULTS: u32 = 8;
    pub const PERF_COUNT_SW_DUMMY: u32 = 9;
    pub const PERF_COUNT_SW_BPF_OUTPUT: u32 = 10;
}

pub(crate) mod perf_event_type {
    #![allow(unused)]
    pub const PERF_RECORD_MMAP: u32 = 1;
    pub const PERF_RECORD_LOST: u32 = 2;
    pub const PERF_RECORD_COMM: u32 = 3;
    pub const PERF_RECORD_EXIT: u32 = 4;
    pub const PERF_RECORD_THROTTLE: u32 = 5;
    pub const PERF_RECORD_UNTHROTTLE: u32 = 6;
    pub const PERF_RECORD_FORK: u32 = 7;
    pub const PERF_RECORD_READ: u32 = 8;
    pub const PERF_RECORD_SAMPLE: u32 = 9;
    pub const PERF_RECORD_MMAP2: u32 = 10;
    pub const PERF_RECORD_AUX: u32 = 11;
    pub const PERF_RECORD_ITRACE_START: u32 = 12;
    pub const PERF_RECORD_LOST_SAMPLES: u32 = 13;
    pub const PERF_RECORD_SWITCH: u32 = 14;
    pub const PERF_RECORD_SWITCH_CPU_WIDE: u32 = 15;
}

pub(crate) mod perf_ioctls {
    pub const PERF_EVENT_IOC_MAGIC: u8 = b'$';
    /// _IO ('$', 0)
    pub const PERF_EVENT_IOC_ENABLE: u8 = 0;
    /// _IO ('$', 1)
    pub const PERF_EVENT_IOC_DISABLE: u8 = 1;
    /// _IO ('$', 2)
    pub const PERF_EVENT_IOC_REFRESH: u8 = 2;
    /// _IO ('$', 3)
    pub const PERF_EVENT_IOC_RESET: u8 = 3;
    /// _IOW('$', 4, __u64)
    pub const PERF_EVENT_IOC_PERIOD: u8 = 4;
    /// _IO ('$', 5)
    pub const PERF_EVENT_IOC_SET_OUTPUT: u8 = 5;
    /// _IOW('$', 6, char *)
    pub const PERF_EVENT_IOC_SET_FILTER: u8 = 6;
    /// _IOR('$', 7, __u64 *)
    pub const PERF_EVENT_IOC_ID: u8 = 7;
    /// _IOW('$', 8, __u32)
    pub const PERF_EVENT_IOC_SET_BPF: u8 = 8;
}

pub(crate) mod perf_flag {
    pub const PERF_FLAG_FD_NO_GROUP: u64 = 1 << 0;
    pub const PERF_FLAG_FD_OUTPUT: u64 = 1 << 1;
    pub const PERF_FLAG_PID_CGROUP: u64 = 1 << 2;
    pub const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;
}
