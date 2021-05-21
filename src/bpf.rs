use libc::syscall;
use nix::errno::errno;
use std::borrow::Borrow;
use std::error::Error;
use std::os::raw::{c_int, c_uint, c_ulong};
use std::os::unix::io::RawFd;
use syscalls::SYS_bpf;
use std::mem::MaybeUninit;

pub enum BpfMapType {
    BPF_MAP_TYPE_UNSPEC = 0, /* Reserve 0 as invalid map type */
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
}

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

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct MapConfig {
    map_type: c_uint,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
union KeyVal {
    value: c_ulong,
    next_key: c_ulong,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct MapElem {
    map_fd: c_uint,
    key: c_ulong,
    keyval: KeyVal,
    flags: c_ulong,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfProgLoad {
    prog_type: c_uint,
    insn_cnt: c_uint,
    insns: c_ulong,   // const struct bpf_insn
    license: c_ulong, // const char *
    log_level: c_uint,
    log_size: c_uint,
    log_buf: c_ulong, // 'char *' buffer
                      //kern_version: c_uint,
}

#[repr(align(8), C)]
union BpfAttr {
    MapConfig: MapConfig,
    MapElem: MapElem,
    BpfProgLoad: BpfProgLoad,
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

unsafe fn sys_bpf(cmd: u32, bpf_attr: Box<BpfAttr>, size: usize) -> Result<usize, i32> {
    let ret = syscall(
        (SYS_bpf as i32).into(),
        cmd,
        bpf_attr.as_ref() as *const _,
        size,
    );
    if ret < 0 {
        return Err(errno());
    }
    Ok(ret as usize)
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

/// Caller is responsible for ensuring T is the correct type for this map
pub(crate) fn bpf_map_lookup_elem<K, V>(map_fd: RawFd, key: K) -> Result<V, i32> {
    let mut buf = MaybeUninit::zeroed();
    let mut map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &mut buf as *mut _ as u64,
        },
        flags: 0,
    };
    let mut bpf_attr = Box::new(BpfAttr { MapElem: map_elem });
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(1, bpf_attr, bpf_attr_size)?;
        Ok(buf.assume_init())
    }
}

fn bpf_map_update_elem<K, V>(map_fd: RawFd, key: K, val: V) -> Result<(), i32> {
    let mut map_elem = MapElem {
        map_fd: map_fd as u32,
        key: &key as *const K as u64,
        keyval: KeyVal {
            value: &val as *const V as u64,
        },
        flags: 0
    };
    let mut bpf_attr = Box::new(BpfAttr { MapElem: map_elem });
    let bpf_attr_size = std::mem::size_of::<MapElem>();
    unsafe {
        sys_bpf(2, bpf_attr, bpf_attr_size)?;
    }
    Ok(())
}

pub(crate) fn bpf_map_create(
    map_type: BpfMapType,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: u32,
) -> Result<RawFd, i32> {
    let mut map_config = MapConfig {
        map_type: map_type as u32,
        key_size: key_size,
        value_size: value_size,
        max_entries: max_entries,
    };
    let mut bpf_attr = Box::new(BpfAttr {
        MapConfig: map_config,
    });
    let bpf_attr_size = std::mem::size_of::<BpfAttr>();

    unsafe {
        let fd = sys_bpf(0, bpf_attr, bpf_attr_size)?;
        Ok(fd as RawFd)
    }
}

#[cfg(test)]
mod tests {
    use crate::bpf::BpfMapType::BPF_MAP_TYPE_ARRAY;
    use std::os::raw::c_uint;
    use std::os::unix::io::RawFd;

    #[test]
    fn bpf_map_create() {
        match crate::bpf::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ) {
            Err(e) => {
                let err = nix::errno::from_i32(e);
                panic!("code: {:?}", err.desc());
            }
            _ => {}
        }
    }

    #[test]
    fn bpf_map_create_and_read() {
        let fd: RawFd = crate::bpf::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ).unwrap();
        
        match crate::bpf::bpf_map_lookup_elem::<u32, u32>(fd, 0) {
            Ok(val) => { assert_eq!(val, 0); }
            Err(e) => {
                let err = nix::errno::from_i32(e);
                panic!("code: {:?}", err.desc());
            }
        }
    }

    #[test]
    fn bpf_map_create_and_write_and_read() {
        let fd: RawFd = crate::bpf::bpf_map_create(
            BPF_MAP_TYPE_ARRAY,
            std::mem::size_of::<u32>() as c_uint,
            std::mem::size_of::<u32>() as c_uint,
            20,
        ).unwrap();

        match crate::bpf::bpf_map_update_elem::<u32, u32>(fd, 5, 50) {
            Ok(_) => {}
            Err(e) => {
                let err = nix::errno::from_i32(e);
                panic!("code: {:?}", err.desc());
            }
        };

        match crate::bpf::bpf_map_lookup_elem::<u32, u32>(fd, 5) {
            Ok(val) => { assert_eq!(val, 50); }
            Err(e) => {
                let err = nix::errno::from_i32(e);
                panic!("code: {:?}", err.desc());
            }
        }
    }
}
