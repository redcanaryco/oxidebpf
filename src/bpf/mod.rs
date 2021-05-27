use crate::bpf::constant::bpf_prog_type;
use crate::error::OxidebpfError;
use std::convert::TryFrom;
use std::os::raw::{c_int, c_short, c_uchar, c_uint, c_ulong};

pub(crate) mod constant;
pub(crate) mod syscall;

#[repr(C)]
union PerfSample {
    sample_period: c_ulong,
    sample_freq: c_ulong,
}

#[repr(C)]
union PerfWakeup {
    wakeup_events: c_uint,
    wakeup_watermark: c_uint,
}

#[repr(C)]
union PerfBpAddr {
    bp_addr: c_ulong,
    config1: c_ulong,
}

#[repr(C)]
union PerfBpLen {
    bp_len: c_ulong,
    config2: c_ulong,
}

#[repr(C)]
pub(crate) struct PerfEventAttr {
    p_type: c_uint,
    size: c_uint,
    config: c_ulong,
    sample_union: PerfSample,
    sample_type: c_ulong,
    read_format: c_ulong,
    flags: c_ulong,
    wakeup_union: PerfWakeup,
    bp_type: c_uint,
    bp_addr_union: PerfBpAddr,
    bp_len_union: PerfBpLen,
    branch_sample_type: c_ulong, // enum perf_branch_sample_type
    sample_regs_user: c_ulong,
    sample_stack_user: c_uint,
    clockid: c_int,
    sample_regs_intr: c_ulong,
    aux_watermark: c_uint,
    __reserved_2: c_uint, // align to __u64 (manually?) consider align(8)
}

#[repr(align(8), C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MapConfig {
    // Minimum functionality set
    pub(crate) map_type: c_uint,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: c_uint,
    // Optionals as of 5.12.7
    map_flags: Option<c_uint>,
    inner_map_fd: Option<c_uint>,
    numa_node: Option<c_uint>,
    map_name: Option<c_ulong>, // pointer to char array BPF_OBJ_NAME_LEN
    map_ifindex: Option<c_uint>,
    btf_fd: Option<c_uint>,
    btf_key_type_id: Option<c_uint>,
    btf_value_type_id: Option<c_uint>,
    btf_vmlinux_value_type_id: Option<c_uint>,
}

impl TryFrom<&[u8]> for MapConfig {
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<MapConfig>() {
            return Err(OxidebpfError::InvalidMapObject);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
    }
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
    // Minimal functionality set
    prog_type: c_uint,
    insn_cnt: c_uint,
    insns: c_ulong,   // Vec<BpfInsn> -  const struct bpf_insn
    license: c_ulong, // const char *
    log_level: c_uint,
    log_size: c_uint,
    log_buf: c_ulong, // 'char *' buffer
    // Additional functionality set, as of 5.12.7
    kern_version: Option<c_uint>, // not used
    prog_flags: Option<c_uint>,
    prog_name: Option<c_ulong>, // char pointer, length BPF_OBJ_NAME_LEN
    prog_ifindex: Option<c_uint>,
    expected_attach_type: Option<c_uint>,
    prog_btf_fd: Option<c_uint>,
    func_info_rec_size: Option<c_uint>,
    func_info: Option<c_ulong>,
    func_info_cnt: Option<c_uint>,
    line_info_rec_size: Option<c_uint>,
    line_info: Option<c_ulong>,
    line_info_cnt: Option<c_uint>,
    attach_btf_id: Option<c_uint>,
    prog_attach: Option<BpfProgAttach>,
}

#[repr(C)]
#[derive(Clone, Copy)]
union BpfProgAttach {
    attach_prog_fd: c_uint,
    attach_btf_objc_fd: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfMapBatch {
    in_batch: c_ulong,
    out_batch: c_ulong,
    keys: c_ulong,
    values: c_ulong,
    count: c_uint,
    map_fd: c_uint,
    elem_flags: c_ulong,
    flags: c_ulong,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfObj {
    pathname: c_ulong,
    bpf_fd: c_uint,
    file_flags: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfProgTach {
    target_fd: c_uint,
    attach_bpf_fd: c_uint,
    attach_type: c_uint,
    attach_flags: c_uint,
    replace_bpf_fd: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfProgTestRun {
    prog_fd: c_uint,
    retval: c_uint,
    data_size_in: c_uint,
    data_size_out: c_uint,
    data_in: c_ulong,
    data_out: c_ulong,
    repeat: c_uint,
    duration: c_uint,
    ctx_size_in: c_uint,
    ctx_size_out: c_uint,
    ctx_in: c_ulong,
    ctx_out: c_ulong,
    flags: c_uint,
    cpu: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfGetId {
    id: GetIdUnion,
    next_id: c_uint,
    open_flags: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
union GetIdUnion {
    start_id: c_uint,
    prog_id: c_uint,
    map_id: c_uint,
    btf_id: c_uint,
    link_id: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfObjGetInfoByFd {
    bpf_fd: c_uint,
    info_len: c_uint,
    info: c_ulong,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfProgQuery {
    target_fd: c_uint,
    attach_type: c_uint,
    query_flags: c_uint,
    attach_flags: c_uint,
    prog_ids: c_ulong,
    prog_cnt: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfRawTracepointOpen {
    name: c_ulong,
    prog_fd: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfBtfLoad {
    btf: c_ulong,
    btf_log_buf: c_ulong,
    btf_size: c_uint,
    btf_log_size: c_uint,
    btf_log_level: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct TaskFdQuery {
    pid: c_uint,
    fd: c_uint,
    flags: c_uint,
    buf_len: c_uint,
    buf: c_ulong,
    prog_id: c_uint,
    fd_type: c_uint,
    probe_offset: c_ulong,
    probe_addr: c_ulong,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
union LinkTarget {
    target_fd: c_uint,
    target_ifindex: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct LinkTargetIterInfo {
    iter_info: c_ulong,
    iter_info_len: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
union LinkTargetInfo {
    target_btf_id: c_uint,
    info: LinkTargetIterInfo,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfLinkCreate {
    prog_fd: c_uint,
    target: LinkTarget,
    attach_type: c_uint,
    flags: c_uint,
    link_target_info: LinkTargetInfo,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfLinkUpdate {
    link_fd: c_uint,
    new_prog_fd: c_uint,
    flags: c_uint,
    old_prog_fd: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfLinkDetach {
    link_fd: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfEnableStats {
    stat_type: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfIterCreate {
    link_fd: c_uint,
    flags: c_uint,
}

#[repr(align(8), C)]
#[derive(Clone, Copy)]
struct BpfProgBindMap {
    prog_fd: c_uint,
    map_fd: c_uint,
    flags: c_uint,
}

#[repr(align(8), C)]
union BpfAttr {
    // minimum functionality set
    map_config: MapConfig,      // BPF_MAP_CREATE
    map_elem: MapElem,          // BPF_MAP_*_ELEM
    bpf_prog_load: BpfProgLoad, // BPF_PROG_LOAD
    // optional as of 5.12.7
    bpf_map_batch: BpfMapBatch,                    // BPF_MAP_*_BATCH
    bpf_obj: BpfObj,                               // BPF_OBJ_*
    bpf_prog_tach: BpfProgTach,                    // BPF_PROG_ATTACH/DETACH
    bpf_prog_test_run: BpfProgTestRun,             // BPF_PROG_TEST_RUN
    bpf_get_id: BpfGetId,                          // BPF_*_GET_*_ID
    bpf_obj_get_info_by_fd: BpfObjGetInfoByFd,     // BPF_OBJ_GET_INFO_BY_FD
    bpf_prog_query: BpfProgQuery,                  // BPF_PROG_QUERY
    bpf_raw_tracepoint_open: BpfRawTracepointOpen, // BPF_RAW_TRACEPOINT_OPEN
    bpf_btf_load: BpfBtfLoad,                      // BPF_BTF_LOAD,
    task_fd_query: TaskFdQuery,
    bpf_link_create: BpfLinkCreate, // BPF_LINK_CREATE
    bpf_link_update: BpfLinkUpdate, // BPF_LINK_UPDATE
    bpf_link_detach: BpfLinkDetach,
    bpf_enable_state: BpfEnableStats,  // BPF_ENABLE_STATS
    bpf_iter_create: BpfIterCreate,    // BPF_ITER_CREATE
    bpf_prog_bind_map: BpfProgBindMap, // BPF_PROG_BIND_MAP
}

#[derive(Debug, Clone)]
pub(crate) struct BpfCode(pub Vec<BpfInsn>);

impl TryFrom<&[u8]> for BpfCode {
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfInsn>()
            || raw.len() % std::mem::size_of::<BpfInsn>() != 0
        {
            return Err(OxidebpfError::InvalidProgramObject);
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
#[derive(Debug, Clone)]
pub(crate) struct BpfInsn {
    pub code: c_uchar,
    pub regs: c_uchar,
    pub off: c_short,
    pub imm: c_int,
}

impl TryFrom<&[u8]> for BpfInsn {
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfInsn>() {
            return Err(OxidebpfError::InvalidProgramObject);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
    }
}

impl BpfInsn {
    pub fn get_src(&self) -> u8 {
        (self.regs >> 4) & 0xf
    }

    pub fn set_src(&mut self, val: u8) {
        self.regs = (self.regs & 0xf) | (val << 4);
    }

    pub fn get_dst(&self) -> u8 {
        self.regs & 0xf
    }

    pub fn set_dst(&mut self, val: u8) {
        self.regs = (self.regs & 0xf0) | (val & 0xf);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ProgramType {
    Unspec,
    Kprobe,
    Kretprobe,
    Uprobe,
    Uretprobe,
    Tracepoint,
    RawTracepoint,
}

impl From<&ProgramType> for u32 {
    fn from(value: &ProgramType) -> u32 {
        match value {
            ProgramType::Kprobe
            | ProgramType::Kretprobe
            | ProgramType::Uprobe
            | ProgramType::Uretprobe => bpf_prog_type::BPF_PROG_TYPE_KPROBE,
            ProgramType::Tracepoint => bpf_prog_type::BPF_PROG_TYPE_TRACEPOINT,
            ProgramType::RawTracepoint => bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
            ProgramType::Unspec => bpf_prog_type::BPF_PROG_TYPE_UNSPEC,
        }
    }
}

impl From<&str> for ProgramType {
    fn from(value: &str) -> ProgramType {
        match value {
            "kprobe" => ProgramType::Kprobe,
            "kretprobe" => ProgramType::Kretprobe,
            "uprobe" => ProgramType::Uprobe,
            "uretprobe" => ProgramType::Uretprobe,
            "tracepoint" => ProgramType::Tracepoint,
            "rawtracepoint" => ProgramType::RawTracepoint,
            _ => ProgramType::Unspec,
        }
    }
}
