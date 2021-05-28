use crate::bpf::constant::bpf_prog_type;
use crate::error::OxidebpfError;
use std::convert::TryFrom;
use std::ffi::CStr;
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
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MapConfig {
    map_type: c_uint,
    key_size: c_uint,
    value_size: c_uint,
    max_entries: c_uint,
}

impl From<MapDefinition> for MapConfig {
    fn from(def: MapDefinition) -> MapConfig {
        Self {
            map_type: def.map_type,
            key_size: def.key_size,
            value_size: def.value_size,
            max_entries: def.max_entries,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct MapDefinition {
    pub map_type: c_uint,
    pub key_size: c_uint,
    pub value_size: c_uint,
    pub max_entries: c_uint,
    pub map_flags: c_uint,
    pub pinning: c_uint,
    pub namespace: [u8; 256],
}

impl MapDefinition {
    pub fn namespace_to_string(&self) -> Option<String> {
        if let Some(upper) = self.namespace.iter().position(|c| *c == 0) {
            self.namespace
                .get(..upper + 1)
                .map(|data| CStr::from_bytes_with_nul(data).unwrap_or_default())
                .map(|cstr| cstr.to_str().unwrap_or_default())
                .map(str::to_string)
        } else {
            None
        }
    }
}

impl TryFrom<&[u8]> for MapDefinition {
    type Error = OxidebpfError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        // at the very least, we need the first 4 entries.
        if raw.len() < std::mem::size_of::<c_uint>() * 4 {
            return Err(OxidebpfError::InvalidMapObject);
        }
        let mut data = vec![0; std::mem::size_of::<MapDefinition>()];
        for (dst, src) in data.iter_mut().zip(raw) {
            *dst = *src;
        }
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const _) })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blueprint_map_definition_parsing() {
        // test minimal definition
        let minimum = vec![
            0x1, 0x0, 0x0, 0x0, // map_type
            0x2, 0x0, 0x0, 0x0, // key_size
            0x3, 0x0, 0x0, 0x0, // value_size
            0x4, 0x0, 0x0, 0x0, // max_entries
        ];
        let r = MapDefinition::try_from(&minimum[..]).unwrap();
        assert_eq!(r.map_type, 0x1, "map_type: {}", r.map_type);
        assert_eq!(r.key_size, 0x2, "key_size: {}", r.key_size);
        assert_eq!(r.value_size, 0x3, "value_size: {}", r.value_size);
        assert_eq!(r.max_entries, 0x4, "max_entries: {}", r.max_entries);
        assert_eq!(r.map_flags, 0, "map_flags: {}", r.map_flags);
        assert_eq!(r.pinning, 0, "pinning: {}", r.pinning);
        assert_eq!(r.namespace[0], 0, "namespace[0]: {}", r.namespace[0]);

        // test flag definition
        let with_flags = vec![
            0x1, 0x0, 0x0, 0x0, // map_type
            0x2, 0x0, 0x0, 0x0, // key_size
            0x3, 0x0, 0x0, 0x0, // value_size
            0x4, 0x0, 0x0, 0x0, // max_entries
            0x5, 0x0, 0x0, 0x0, // map_flags
        ];
        let r = MapDefinition::try_from(&with_flags[..]).unwrap();
        assert_eq!(r.map_type, 0x1, "map_type: {}", r.map_type);
        assert_eq!(r.key_size, 0x2, "key_size: {}", r.key_size);
        assert_eq!(r.value_size, 0x3, "value_size: {}", r.value_size);
        assert_eq!(r.max_entries, 0x4, "max_entries: {}", r.max_entries);
        assert_eq!(r.map_flags, 0x5, "map_flags: {}", r.map_flags);
        assert_eq!(r.pinning, 0, "pinning: {}", r.pinning);

        // test with namespace
        let with_namespace = vec![
            0x1, 0x0, 0x0, 0x0, // map_type
            0x2, 0x0, 0x0, 0x0, // key_size
            0x3, 0x0, 0x0, 0x0, // value_size
            0x4, 0x0, 0x0, 0x0, // max_entries
            0x5, 0x0, 0x0, 0x0, // map_flags
            0x1, 0x0, 0x0, 0x0, // pinning
            0x74, 0x65, 0x73, 0x74, // "test"
            0, 0,
        ];
        let r = MapDefinition::try_from(&with_namespace[..]).unwrap();
        assert_eq!(r.map_type, 0x1, "map_type: {}", r.map_type);
        assert_eq!(r.key_size, 0x2, "key_size: {}", r.key_size);
        assert_eq!(r.value_size, 0x3, "value_size: {}", r.value_size);
        assert_eq!(r.max_entries, 0x4, "max_entries: {}", r.max_entries);
        assert_eq!(r.map_flags, 0x5, "map_flags: {}", r.map_flags);
        assert_eq!(r.pinning, 1, "pinning: {}", r.pinning);
        assert_eq!(
            r.namespace_to_string(),
            Some("test".to_string()),
            "namespace string: {:?}",
            r.namespace_to_string()
        );
    }
}
