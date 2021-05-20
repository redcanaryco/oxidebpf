use libc::{syscall, SYS_bpf};
use std::os::raw::{c_uint, c_ulong};

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
    insns: c_ulong, // const struct bpf_insn
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
    syscall(SYS_bpf, cmd, /* bpf_attr union */, /* size of union */)
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
