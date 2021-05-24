use goblin::elf::{header, section_header, Elf, SectionHeader};
use std::convert::TryFrom;
use std::ffi::CStr;

use crate::bpf::*;
use crate::error::*;
use crate::sys::get_kernel_version;

/// Structure that parses and holds eBPF objects from an ELF object.
#[derive(Clone, Default)]
pub(crate) struct ProgramBlueprint {
    pub objects: Vec<EbpfObject>,
}

impl ProgramBlueprint {
    pub fn new(data: &[u8]) -> Result<Self, EbpfObjectError> {
        let elf: Elf = parse_and_verify_elf(data)?;
        let mut blueprint = Self::default();

        for (sh_index, sh) in elf
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| sh.sh_type == section_header::SHT_PROGBITS && sh.sh_size > 0)
        {
            blueprint
                .objects
                .extend(EbpfObject::from_section(data, &elf, sh_index, sh)?);
        }

        Ok(blueprint)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum EbpfObject {
    Map(MapObject),
    Program(ProgramObject),
}

impl EbpfObject {
    fn from_section<'a>(
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<Self>, EbpfObjectError> {
        let section_name = get_section_name(&elf, sh).unwrap_or_default();
        let mut name_split = section_name.splitn(2, '/');
        let prefix = name_split.next().unwrap_or_default();
        let name = name_split.next();

        Ok(match (prefix, name) {
            ("maps", Some(name)) => MapObject::from_section(name, data, elf, sh_index, sh)?,
            ("kprobe", Some(name)) => {
                ProgramObject::from_section(ProgramType::Kprobe, name, data, elf, sh_index, sh)?
            }
            ("kretprobe", Some(name)) => {
                ProgramObject::from_section(ProgramType::Kretprobe, name, data, elf, sh_index, sh)?
            }
            ("uprobe", Some(name)) => {
                ProgramObject::from_section(ProgramType::Uprobe, name, data, elf, sh_index, sh)?
            }
            ("uretprobe", Some(name)) => {
                ProgramObject::from_section(ProgramType::Uretprobe, name, data, elf, sh_index, sh)?
            }
            _ => return Err(EbpfObjectError::UnknownObject(format!("{}", section_name))),
        })
    }
}

///@TODO: This will need to be merged with the struct in lib.rs
#[derive(Debug, Clone)]
pub(crate) struct ProgramObject {
    pub kind: ProgramType,
    pub name: String,
    pub code: BpfCode,
    relocations: Vec<Reloc>,
    pub license: String,
    pub version: u32,
}

impl ProgramObject {
    fn from_section<'a>(
        kind: ProgramType,
        name: &str,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<EbpfObject>, EbpfObjectError> {
        let code = BpfCode::try_from(get_section_data(data, sh))?;
        Ok(vec![EbpfObject::Program(ProgramObject {
            kind,
            name: name.to_string(),
            code,
            relocations: Reloc::get_relocs_for_program(sh_index, &elf)?,
            license: get_license(data, elf),
            version: get_version(data, elf),
        })])
    }

    /// Returns a list of map symbol names that this program requires
    pub(crate) fn required_maps(&self) -> Vec<String> {
        self.relocations
            .iter()
            .map(|r| r.symbol_name.clone())
            .collect()
    }

    /// Performs relocation fixups given an array of loaded maps.
    pub(crate) fn apply_relocations(&self, maps: &[MapObject]) -> Result<(), EbpfObjectError> {
        //@TODO
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BpfCode(pub Vec<BpfInsn>);

impl TryFrom<&[u8]> for BpfCode {
    type Error = EbpfObjectError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfInsn>()
            || raw.len() % std::mem::size_of::<BpfInsn>() != 0
        {
            return Err(EbpfObjectError::InvalidElf);
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

#[derive(Debug, Clone)]
pub(crate) struct Reloc {
    /// Symbol name for the relocation.
    pub symbol_name: String,
    /// The instruction to apply the relocation to
    pub insn_index: u64,
    /// The type of relocation. (R_BPF_64_32, R_BPF_64_64,)
    pub kind: u32,
}

impl Reloc {
    /// Retrieve the section relocations for a given program section index
    fn get_relocs_for_program(
        program_index: usize,
        elf: &Elf,
    ) -> Result<Vec<Self>, EbpfObjectError> {
        // find the relocation index
        let reloc_index = elf
            .section_headers
            .iter()
            .enumerate()
            .find(|(index, sh)| {
                sh.sh_type == section_header::SHT_REL && sh.sh_info == program_index as u32
            })
            .map(|(reloc_index, reloc_sh)| reloc_index);

        // If we cant find a relocation section for the program section, assume it has no relocations
        if reloc_index.is_none() {
            return Ok(Vec::new());
        }

        // retrieve the relocation section
        let reloc_section = elf
            .shdr_relocs
            .iter()
            .find(|(index, relocs)| *index == reloc_index.unwrap())
            .map(|(index, relocs)| relocs)
            .ok_or(EbpfObjectError::InvalidElf)?;

        Ok(reloc_section
            .iter()
            .map(|r| Reloc {
                symbol_name: get_symbol_name(&elf, r.r_sym).unwrap_or_default(),
                insn_index: r.r_offset / std::mem::size_of::<BpfInsn>() as u64,
                kind: r.r_type,
            })
            .collect())
    }
}

///@TODO: This will need to be merged with the struct in lib.rs
#[derive(Debug, Clone)]
pub(crate) struct MapObject {
    pub definition: BpfMapDef,
    /// The name of the map
    pub name: String,
    /// The symbol name of the map
    pub symbol_name: String,
}

impl MapObject {
    fn from_section<'a>(
        name: &str,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<EbpfObject>, EbpfObjectError> {
        let symbol_name = elf
            .syms
            .iter()
            .find(|sym| sym.st_shndx == sh_index)
            .map(|sym| get_symbol_name(elf, sym.st_name).unwrap_or_default());
        Ok(vec![EbpfObject::Map(MapObject {
            definition: BpfMapDef::try_from(get_section_data(data, sh))?,
            name: name.to_string(),
            symbol_name: symbol_name.unwrap_or_default(),
        })])
    }
}

/// The map definition found in an eBPF object.
/// * @TODO: Possibly a duplicate of `MapConfig`
#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct BpfMapDef {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl TryFrom<&[u8]> for BpfMapDef {
    type Error = EbpfObjectError;
    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if raw.len() < std::mem::size_of::<BpfMapDef>() {
            return Err(EbpfObjectError::InvalidElf);
        }
        Ok(unsafe { std::ptr::read(raw.as_ptr() as *const _) })
    }
}

fn get_section_name<'a>(elf: &'a Elf, sh: &'a SectionHeader) -> Option<&'a str> {
    elf.shdr_strtab.get_unsafe(sh.sh_name)
}

fn get_section_data<'a>(data: &'a [u8], sh: &'a SectionHeader) -> &'a [u8] {
    &data[sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize]
}

fn get_section_by_name<'a>(elf: &'a Elf, name: &str) -> Option<&'a SectionHeader> {
    elf.section_headers
        .iter()
        .find(|sh| get_section_name(elf, sh) == Some(name))
}

fn get_license(data: &[u8], elf: &Elf) -> String {
    get_section_by_name(elf, "license")
        .map(|sh| CStr::from_bytes_with_nul(get_section_data(data, sh)))
        .map(|s| s.unwrap_or_default().to_str().unwrap_or_default())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn get_version(data: &[u8], elf: &Elf) -> u32 {
    const MAGIC_VERSION: u32 = 0xFFFFFFFE;
    let version = get_section_by_name(elf, "version")
        .map(|section| get_section_data(data, section))
        .filter(|s_data| s_data.len() == 4)
        .map(|s_data| {
            let mut int_data: [u8; 4] = Default::default();
            int_data.copy_from_slice(s_data);
            u32::from_ne_bytes(int_data)
        })
        .unwrap_or(MAGIC_VERSION);

    if version == MAGIC_VERSION {
        get_kernel_version()
    } else {
        version
    }
}

fn get_symbol_name(elf: &Elf, sym_index: usize) -> Option<String> {
    elf.syms.get(sym_index as usize).map(|sym| {
        elf.strtab
            .get(sym.st_name)
            .map(|r| r.map(str::to_owned).unwrap_or_default())
            .unwrap_or_default()
    })
}

fn parse_and_verify_elf(data: &[u8]) -> Result<Elf, EbpfObjectError> {
    let elf = Elf::parse(data).map_err(|_e| EbpfObjectError::InvalidElf)?;

    match elf.header.e_machine {
        header::EM_BPF | header::EM_NONE => (),
        val => return Err(EbpfObjectError::InvalidElfMachine),
    }

    Ok(elf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
