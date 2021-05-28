pub(crate) mod bpf_prog_type {
    #![allow(unused)]
    pub const BPF_PROG_TYPE_UNSPEC: u32 = 0;
    pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
    pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
    pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
    pub const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;
    pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
    pub const BPF_PROG_TYPE_XDP: u32 = 6;
    pub const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
    pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
    pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
    pub const BPF_PROG_TYPE_LWT_IN: u32 = 10;
    pub const BPF_PROG_TYPE_LWT_OUT: u32 = 11;
    pub const BPF_PROG_TYPE_LWT_XMIT: u32 = 12;
    pub const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
    pub const BPF_PROG_TYPE_SK_SKB: u32 = 14;
    pub const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
    pub const BPF_PROG_TYPE_SK_MSG: u32 = 16;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
    pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
    pub const BPF_PROG_TYPE_LWT_SEG6LOCAL: u32 = 19;
    pub const BPF_PROG_TYPE_LIRC_MODE2: u32 = 20;
    pub const BPF_PROG_TYPE_SK_REUSEPORT: u32 = 21;
    pub const BPF_PROG_TYPE_FLOW_DISSECTOR: u32 = 22;
    pub const BPF_PROG_TYPE_CGROUP_SYSCTL: u32 = 23;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24;
    pub const BPF_PROG_TYPE_CGROUP_SOCKOPT: u32 = 25;
    pub const BPF_PROG_TYPE_TRACING: u32 = 26;
    pub const BPF_PROG_TYPE_STRUCT_OPS: u32 = 27;
    pub const BPF_PROG_TYPE_EXT: u32 = 28;
    pub const BPF_PROG_TYPE_LSM: u32 = 29;
    pub const BPF_PROG_TYPE_SK_LOOKUP: u32 = 30;
}

pub(crate) mod bpf_map_type {
    #![allow(unused)]
    pub const BPF_MAP_TYPE_UNSPEC: u32 = 0;
    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
    pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
    pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
    pub const BPF_MAP_TYPE_CGROUP_ARRAY: u32 = 8;
    pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
    pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
    pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
    pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
    pub const BPF_MAP_TYPE_HASH_OF_MAPS: u32 = 13;
    pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;
    pub const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
    pub const BPF_MAP_TYPE_CPUMAP: u32 = 16;
    pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
    pub const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
    pub const BPF_MAP_TYPE_CGROUP_STORAGE: u32 = 19;
    pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: u32 = 20;
    pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: u32 = 21;
    pub const BPF_MAP_TYPE_QUEUE: u32 = 22;
    pub const BPF_MAP_TYPE_STACK: u32 = 23;
    pub const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
    pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
}

pub(crate) mod bpf_cmd {
    #![allow(unused)]
    pub const BPF_MAP_CREATE: u32 = 0;
    pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
    pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
    pub const BPF_MAP_DELETE_ELEM: u32 = 3;
    pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
    pub const BPF_PROG_LOAD: u32 = 5;
    pub const BPF_OBJ_PIN: u32 = 6;
    pub const BPF_OBJ_GET: u32 = 7;
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
    #![allow(unused)]
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
