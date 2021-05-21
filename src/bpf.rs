use libc::{syscall, SYS_bpf};
use std::convert::{From, TryFrom};
use std::os::raw::{c_int, c_short, c_uchar, c_uint, c_ulong};

use crate::error::*;

// TODO: bpf_attr struct
// union bpf_attr {
//     struct {    /* Used by BPF_MAP_CREATE */
//     __u32         map_type;
//     __u32         key_size;    /* size of key in bytes */
//     __u32         value_size;  /* size of value in bytes */
//     __u32         max_entries; /* maximum number of entries
//                                                  in a map */
//     };
//
//     struct {    /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY
//                               commands */
//     __u32         map_fd;
//     __aligned_u64 key;
//     union {
//     __aligned_u64 value;
//     __aligned_u64 next_key;
//     };
//     __u64         flags;
//     };
//
//     struct {    /* Used by BPF_PROG_LOAD */
//     __u32         prog_type;
//     __u32         insn_cnt;
//     __aligned_u64 insns;      /* 'const struct bpf_insn *' */
//     __aligned_u64 license;    /* 'const char *' */
//     __u32         log_level;  /* verbosity level of verifier */
//     __u32         log_size;   /* size of user buffer */
//     __aligned_u64 log_buf;    /* user supplied 'char *'
//                                                 buffer */
//     __u32         kern_version;
//     /* checked when prog_type=kprobe
//        (since Linux 4.1) */
//     };
// } __attribute__((aligned(8)));

// TODO: guaranteed alignment crate

#[repr(C)]
struct MapConfig {
    map_type: c_uint,
    key_size: c_uint,
    value_size: c_uint,
    max_entires: c_uint,
}

#[repr(C)]
union KeyVal {
    value: c_ulong,
    next_key: c_ulong,
}

#[repr(C)]
struct MapElem {
    map_fd: c_uint,
    key: c_ulong,
    keyval: KeyVal,
    flags: c_ulong,
}

#[repr(C)]
struct BpfProgLoad {
    prog_type: c_uint,
    insn_cnt: c_uint,
    insns: c_ulong,   // const struct bpf_insn
    license: c_ulong, // const char *
    log_level: c_uint,
    log_size: c_uint,
    log_buf: c_ulong, // 'char *' buffer
    kern_version: c_uint,
}

#[repr(C)] // or #[repr(align(8))] ?
union bpf_attr {
    map_config: MapConfig,
    map_elem: MapElem,
    bpf_prog_load: BpfProgLoad,
}

#[derive(Clone)]
pub(crate) struct BpfCode(pub Vec<BpfInsn>);

impl TryFrom<&[u8]> for BpfCode {
    type Error = EbpfParserError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        println!("{} {}", raw.len(), std::mem::size_of::<BpfInsn>());
        if raw.len() < std::mem::size_of::<BpfInsn>()
            || raw.len() % std::mem::size_of::<BpfInsn>() != 0
        {
            return Err(EbpfParserError::InvalidElf);
        }
        let mut instructions: Vec<BpfInsn> = Vec::new();
        for i in (0..raw.len()).step_by(std::mem::size_of::<BpfInsn>()) {
            instructions.push(BpfInsn::try_from(
                &raw[i..i + std::mem::size_of::<BpfInsn>()],
            )?);
        }
        Ok(BpfCode(instructions))
    }
}

#[repr(C)]
#[derive(Clone)]
pub(crate) struct BpfInsn {
    pub code: c_uchar,
    pub regs: c_uchar,
    pub off: c_short,
    pub imm: c_int,
}

impl TryFrom<&[u8]> for BpfInsn {
    type Error = EbpfParserError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfInsn>() {
            return Err(EbpfParserError::InvalidElf);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
    }
}

/// The map definition found in an eBPF object.
/// Unsupported fields: `pinned` and `namespace`
/// * @TODO: Possibly a duplicate of `MapConfig`
#[repr(C)]
#[derive(Clone)]
pub(crate) struct BpfMapDef {
    pub map_type: c_uint,
    pub key_size: c_uint,
    pub value_size: c_uint,
    pub max_entries: c_uint,
    pub map_flags: c_uint,
}

impl TryFrom<&[u8]> for BpfMapDef {
    type Error = EbpfParserError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfMapDef>() {
            return Err(EbpfParserError::InvalidElf);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum ObjectMapType {
    Unspec,
    Map,
    Data,
    Bss,
    RoData,
}

impl From<&str> for ObjectMapType {
    fn from(value: &str) -> Self {
        match value {
            ".bss" => ObjectMapType::Bss,
            ".data" => ObjectMapType::Data,
            ".rodata" => ObjectMapType::RoData,
            "maps" => ObjectMapType::Map,
            _ => ObjectMapType::Unspec,
        }
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum ObjectProgramType {
    Unspec,
    Kprobe,
    Kretprobe,
    Uprobe,
    Uretprobe,
    Tracepoint,
    RawTracepoint,
}

impl From<ObjectProgramType> for u32 {
    fn from(value: ObjectProgramType) -> u32 {
        match value {
            ObjectProgramType::Kprobe
            | ObjectProgramType::Kretprobe
            | ObjectProgramType::Uprobe
            | ObjectProgramType::Uretprobe => bpf_prog_type::BPF_PROG_TYPE_KPROBE,
            ObjectProgramType::Tracepoint => bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT,
            ObjectProgramType::RawTracepoint => bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
            ObjectProgramType::Unspec => bpf_map_type::BPF_PROG_TYPE_UNSPEC,
        }
    }
}

impl From<&str> for ObjectProgramType {
    fn from(value: &str) -> Self {
        match value {
            "kprobe" => ObjectProgramType::Kprobe,
            "kretprobe" => ObjectProgramType::Kretprobe,
            "uprobe" => ObjectProgramType::Uprobe,
            "uretprobe" => ObjectProgramType::Uretprobe,
            "tracepoint" => ObjectProgramType::Tracepoint,
            "rawtracepoint" => ObjectProgramType::RawTracepoint,
            _ => ObjectProgramType::Unspec,
        }
    }
}

mod bpf_prog_type {
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

mod bpf_map_type {
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

// https://man7.org/linux/man-pages/man2/syscall.2.html
// Architecture-specific requirements
// Each architecture ABI has its own requirements on how system call
// arguments are passed to the kernel.  For system calls that have a
// glibc wrapper (e.g., most system calls), glibc handles the
// details of copying arguments to the right registers in a manner
// suitable for the architecture.  However, when using syscall() to
// make a system call, the caller might need to handle architecture-
// dependent details; this requirement is most commonly encountered
// on certain 32-bit architectures.

unsafe fn sys_bpf(cmd: u32) -> i32 {
    //@TODO: fix
    // syscall(SYS_bpf, cmd, /* bpf_attr union */, /* size of union */)
    0
}

// perf_event_open
// https://man7.org/linux/man-pages/man2/perf_event_open.2.html
// Glibc does not provide a wrapper for this system call; call it
// using syscall(2).  See the example below.
//
// The official way of knowing if perf_event_open() support is
// enabled is checking for the existence of the file
// /proc/sys/kernel/perf_event_paranoid.
fn perf_event_open() {
    unimplemented!()
}

// setns
fn setns() {
    unimplemented!()
}

// ioctl( PERF_EVENT_IOC_SET_BPF )
fn perf_event_ioc_set_bpf() {
    unimplemented!()
}

// ioctl( PERF_EVENT_IOC_ENABLE )
fn perf_event_ioc_enable() {
    unimplemented!()
}

// ioctl( PERF_EVENT_IOC_DISABLE )
fn perf_event_ioc_disable() {
    unimplemented!()
}

// syscall( BPF_PROG_LOAD )
fn bpf_prog_load() {
    unimplemented!()
}

// bpf_map_lookup_elem()
fn bpf_map_lookup_elem() {
    unimplemented!()
}

// bpf_map_update_elem()
fn bpf_map_update_elem() {
    unimplemented!()
}
