use goblin::elf::{header, section_header, Elf, SectionHeader, Sym};
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::unix::io::RawFd;

use crate::bpf::*;
use crate::error::*;

/// Structure that parses and holds eBPF objects from an ELF object.
#[derive(Debug, Clone, Default)]
pub struct ProgramBlueprint {
    pub(crate) objects: Vec<EbpfObject>,
}

/// Parses a section and produces a vector of ebpf objects.
///
/// Arguments:
/// object_data - bytes of the ELF object file
/// elf - the parsed ELF object
/// section_index - the section index being parsed
///
/// Returns
pub type SectionParser = fn(
    object_data: &[u8],
    elf: &Elf,
    section_index: usize,
) -> Result<Vec<EbpfObject>, OxidebpfError>;

impl ProgramBlueprint {
    pub fn new(data: &[u8], parser: Option<SectionParser>) -> Result<Self, OxidebpfError> {
        let elf: Elf = parse_and_verify_elf(data)?;
        let mut blueprint = Self::default();

        for (sh_index, sh) in elf
            .section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| sh.sh_type == section_header::SHT_PROGBITS && sh.sh_size > 0)
        {
            let section_name = get_section_name(&elf, sh).unwrap_or_default();
            let mut name_split = section_name.splitn(2, '/');
            let prefix = name_split.next().unwrap_or_default();
            let name = name_split.next();

            blueprint.objects.extend(match (prefix, name) {
                ("maps", name) => MapObject::from_section(name, data, &elf, sh_index, sh)?,
                ("kprobe", Some(name)) => ProgramObject::from_section(
                    ProgramType::Kprobe,
                    name,
                    data,
                    &elf,
                    sh_index,
                    sh,
                )?,
                ("kretprobe", Some(name)) => ProgramObject::from_section(
                    ProgramType::Kretprobe,
                    name,
                    data,
                    &elf,
                    sh_index,
                    sh,
                )?,
                ("uprobe", Some(name)) => ProgramObject::from_section(
                    ProgramType::Uprobe,
                    name,
                    data,
                    &elf,
                    sh_index,
                    sh,
                )?,
                ("uretprobe", Some(name)) => ProgramObject::from_section(
                    ProgramType::Uretprobe,
                    name,
                    data,
                    &elf,
                    sh_index,
                    sh,
                )?,
                _ => {
                    if let Some(parser) = parser {
                        parser(data, &elf, sh_index)?
                    } else {
                        Vec::new()
                    }
                }
            });
        }

        Ok(blueprint)
    }
}

#[derive(Debug, Clone)]
pub enum EbpfObject {
    Map(MapObject),
    Program(ProgramObject),
}

#[derive(Debug, Clone)]
pub struct ProgramObject {
    pub(crate) kind: ProgramType,
    pub(crate) name: String,
    code: BpfCode,
    relocations: Vec<Reloc>,
    pub(crate) license: String,
}

impl ProgramObject {
    fn from_section<'a>(
        kind: ProgramType,
        name: &str,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<EbpfObject>, OxidebpfError> {
        let section_data = get_section_data(data, sh).ok_or(OxidebpfError::InvalidElf)?;
        let code = BpfCode::try_from(section_data)?;
        Ok(vec![EbpfObject::Program(ProgramObject {
            kind,
            name: name.to_string(),
            code,
            relocations: Reloc::get_map_relocations(sh_index, &elf)?,
            license: get_license(data, elf),
        })])
    }

    /// Returns a list of map symbol names that this program requires
    pub(crate) fn required_maps(&self) -> Vec<String> {
        self.relocations
            .iter()
            .map(|r| r.symbol_name.clone())
            .collect()
    }

    /// Perform fixups for loaded maps
    pub(crate) fn fixup_map_relocation(
        &mut self,
        fd: RawFd,
        map: &MapObject,
    ) -> Result<(), OxidebpfError> {
        if self.relocations.len() == 0 {
            return Ok(());
        }

        let reloc = self
            .relocations
            .iter()
            .find(|r| r.symbol_name == map.symbol_name)
            .ok_or(OxidebpfError::InvalidProgramObject)?;

        if let Some(insn) = self.code.0.get_mut(reloc.insn_index as usize) {
            insn.set_src(1);
            insn.imm = fd as i32;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Reloc {
    pub symbol_name: String,
    /// The instruction to apply the relocation to
    pub insn_index: u64,
    /// The type of relocation. (R_BPF_64_32, R_BPF_64_64,)
    pub kind: u32,
}

impl Reloc {
    /// Retrieve the section relocations for a given program section index
    fn get_map_relocations(program_index: usize, elf: &Elf) -> Result<Vec<Self>, OxidebpfError> {
        // find the relocation index
        let reloc_index = elf
            .section_headers
            .iter()
            .enumerate()
            .find(|(_index, sh)| {
                sh.sh_type == section_header::SHT_REL && sh.sh_info == program_index as u32
            })
            .map(|(reloc_index, _)| reloc_index);

        // If we cant find a relocation section for the program section, assume it has no relocations
        if reloc_index.is_none() {
            return Ok(Vec::new());
        }

        // retrieve the relocation section
        let reloc_section = elf
            .shdr_relocs
            .iter()
            .find(|(index, _relocs)| *index == reloc_index.unwrap())
            .map(|(_index, relocs)| relocs)
            .ok_or(OxidebpfError::InvalidProgramObject)?;

        Ok(reloc_section
            .iter()
            .filter_map(|r| {
                if let Some(sym) = elf.syms.get(r.r_sym) {
                    Some(Reloc {
                        symbol_name: get_symbol_name(&elf, &sym).unwrap_or_default(),
                        insn_index: r.r_offset / std::mem::size_of::<BpfInsn>() as u64,
                        kind: r.r_type,
                    })
                } else {
                    None
                }
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct MapObject {
    /// The map definition parsed out of the eBPF ELF object
    pub(crate) definition: MapConfig,
    /// The name of the map
    pub(crate) name: String,
    /// The symbol name of the map
    pub(crate) symbol_name: String,
}

impl MapObject {
    fn from_section<'a>(
        section_name: Option<&str>,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<EbpfObject>, OxidebpfError> {
        let mut objects = Vec::new();
        let section_data = get_section_data(data, sh).ok_or(OxidebpfError::InvalidElf)?;

        // Assume that all symbols in this section are map definitions.
        for (index, sym) in elf
            .syms
            .iter()
            .filter(|sym| sym.st_shndx == sh_index)
            .enumerate()
        {
            let symbol_name = get_symbol_name(elf, &sym).unwrap_or_default();
            // If a section name was provided (which does not include the "maps/" prefix)
            // then we use that. Otherwise we use the symbol name.
            let name = if index == 0 && section_name.is_some() {
                section_name.unwrap_or_default().to_string()
            } else {
                symbol_name.clone()
            };

            if let Some(map_data) =
                section_data.get(sym.st_value as usize..section_data.len() as usize)
            {
                objects.push(EbpfObject::Map(MapObject {
                    definition: MapConfig::try_from(map_data)?,
                    name,
                    symbol_name,
                }));
            }
        }

        Ok(objects)
    }
}

fn get_section_name<'a>(elf: &'a Elf, sh: &'a SectionHeader) -> Option<&'a str> {
    elf.shdr_strtab.get_unsafe(sh.sh_name)
}

fn get_section_data<'a>(data: &'a [u8], sh: &'a SectionHeader) -> Option<&'a [u8]> {
    data.get(sh.sh_offset as usize..(sh.sh_offset + sh.sh_size) as usize)
}

fn get_section_by_name<'a>(elf: &'a Elf, name: &str) -> Option<&'a SectionHeader> {
    elf.section_headers
        .iter()
        .find(|sh| get_section_name(elf, sh) == Some(name))
}

fn get_license(data: &[u8], elf: &Elf) -> String {
    get_section_by_name(elf, "license")
        .and_then(|sh| get_section_data(data, sh))
        .map(|section_data| CStr::from_bytes_with_nul(section_data))
        .map(|s| s.unwrap_or_default().to_str().unwrap_or_default())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn get_symbol_name(elf: &Elf, sym: &Sym) -> Option<String> {
    elf.strtab
        .get(sym.st_name)
        .map(|r| r.map(str::to_owned).unwrap_or_default())
}

fn parse_and_verify_elf(data: &[u8]) -> Result<Elf, OxidebpfError> {
    let elf = Elf::parse(data).map_err(|_e| OxidebpfError::InvalidElf)?;

    match elf.header.e_machine {
        header::EM_BPF | header::EM_NONE => (),
        _ => return Err(OxidebpfError::InvalidElf),
    }

    Ok(elf)
}
