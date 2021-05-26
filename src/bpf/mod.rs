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
    map_type: c_uint,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: c_uint,
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
