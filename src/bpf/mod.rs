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
#[derive(Clone, Copy)]
pub(crate) struct MapConfig {
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
    insns: c_ulong,   // Vec<BpfInsn> -  const struct bpf_insn
    license: c_ulong, // const char *
    log_level: c_uint,
    log_size: c_uint,
    log_buf: c_ulong, // 'char *' buffer
                      //kern_version: c_uint,
}

#[repr(align(8), C)]
union BpfAttr {
    map_config: MapConfig,
    map_elem: MapElem,
    bpf_prog_load: BpfProgLoad,
}

#[derive(Clone)]
pub(crate) struct BpfCode(pub Vec<BpfInsn>);

impl TryFrom<&[u8]> for BpfCode {
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        println!("{} {}", raw.len(), std::mem::size_of::<BpfInsn>());
        if raw.len() < std::mem::size_of::<BpfInsn>()
            || raw.len() % std::mem::size_of::<BpfInsn>() != 0
        {
            return Err(OxidebpfError::InvalidElf);
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
            return Err(OxidebpfError::InvalidElf);
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
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfMapDef>() {
            return Err(OxidebpfError::InvalidElf);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
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

impl From<ProgramType> for u32 {
    fn from(value: ProgramType) -> u32 {
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
