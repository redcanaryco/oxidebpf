use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::unix::io::RawFd;

use goblin::elf::{header, section_header, Elf, SectionHeader, Sym};
use itertools::Itertools;

use crate::bpf::*;
use crate::error::*;
use crate::ProgramType;

/// Structure that parses eBPF objects from an ELF object.
#[derive(Debug, Clone, Default)]
pub struct ProgramBlueprint {
    pub(crate) maps: HashMap<String, MapObject>,
    pub(crate) programs: HashMap<String, ProgramObject>,
}

/// This enum lets the ProgramBlueprint know how to parse sections not covered in our eBPF ABI.
#[derive(Debug, Clone)]
pub enum SectionType<'a> {
    Map {
        /// The name of the section prefix.
        section_prefix: &'a str,
    },
    Program {
        /// The name of the section prefix.
        section_prefix: &'a str,
        /// The type of program ("kprobe", "kretprobe", "uprobe",...)
        program_type: &'a str,
    },
}

impl<'a> SectionType<'a> {
    fn prefix_matches(&self, other: &str) -> bool {
        match self {
            Self::Map { section_prefix, .. } => *section_prefix == other,
            Self::Program { section_prefix, .. } => *section_prefix == other,
        }
    }
}

impl ProgramBlueprint {
    pub fn new(
        data: &[u8],
        section_types: Option<Vec<SectionType>>,
    ) -> Result<Self, OxidebpfError> {
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

            // First check to see if section name matches any of the prefixes that we expect.
            match prefix {
                "maps" => {
                    for obj in MapObject::from_section(name, data, &elf, sh_index, sh)?.into_iter()
                    {
                        blueprint.maps.insert(obj.symbol_name.clone(), obj);
                    }
                    continue;
                }
                "kprobe" | "kretprobe" | "uprobe" | "uretprobe" => {
                    let obj =
                        ProgramObject::from_section(prefix.into(), name, data, &elf, sh_index, sh)?;
                    blueprint.programs.insert(obj.name.clone(), obj);
                    continue;
                }
                _ => (),
            }

            // check to see if the section matches up with the section definitions the user passed in
            for section_type in section_types
                .iter()
                .flat_map(|s| s)
                .filter(|s| s.prefix_matches(prefix))
            {
                match section_type {
                    SectionType::Map { .. } => {
                        for obj in
                            MapObject::from_section(name, data, &elf, sh_index, sh)?.into_iter()
                        {
                            blueprint.maps.insert(obj.symbol_name.clone(), obj);
                        }
                    }
                    SectionType::Program { program_type, .. } => {
                        let obj = ProgramObject::from_section(
                            (*program_type).into(),
                            name,
                            data,
                            &elf,
                            sh_index,
                            sh,
                        )?;
                        blueprint.programs.insert(obj.name.clone(), obj);
                    }
                }
            }
        }

        Ok(blueprint)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ProgramObject {
    pub program_type: ProgramType,
    pub name: String,
    pub(crate) code: BpfCode,
    relocations: Vec<Reloc>,
    pub license: String,
}

impl ProgramObject {
    fn from_section<'a>(
        program_type: ProgramType,
        name: Option<&str>,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Self, OxidebpfError> {
        let section_data = get_section_data(data, sh).ok_or(OxidebpfError::InvalidElf)?;
        let code = BpfCode::try_from(section_data)?;

        let symbol_name = elf
            .syms
            .iter()
            .filter(|sym| sym.st_shndx == sh_index)
            .next()
            .map(|sym| get_symbol_name(&elf, &sym).unwrap_or_default())
            .unwrap_or_default();

        // For object naming, we prioritize the section name over the symbol name
        Ok(Self {
            program_type,
            name: name.map(str::to_string).unwrap_or(symbol_name),
            code,
            relocations: Reloc::get_map_relocations(sh_index, &elf)?,
            license: get_license(data, elf),
        })
    }

    /// Returns a list of map symbol names that this program requires
    pub(crate) fn required_maps(&self) -> Vec<String> {
        self.relocations
            .iter()
            .map(|r| r.symbol_name.clone())
            .unique()
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
    pub reloc_type: u32,
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
                        reloc_type: r.r_type,
                    })
                } else {
                    None
                }
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MapObject {
    /// The map definition parsed out of the eBPF ELF object
    pub definition: MapDefinition,
    /// The name of the map
    pub name: String,
    /// The symbol name of the map
    pub symbol_name: String,
}

impl MapObject {
    fn from_section<'a>(
        section_name: Option<&str>,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
    ) -> Result<Vec<Self>, OxidebpfError> {
        let mut objects = Vec::new();
        let section_data = get_section_data(data, sh).ok_or(OxidebpfError::InvalidElf)?;

        // Assume that all symbols in this section are map definitions.
        for sym in elf.syms.iter().filter(|sym| sym.st_shndx == sh_index) {
            let symbol_name = get_symbol_name(elf, &sym).unwrap_or_default();
            // If a section name was provided (which does not include the "maps/" prefix)
            // then we use that. Otherwise we use the symbol name.
            let name = section_name
                .map(str::to_string)
                .unwrap_or_else(|| symbol_name.clone());

            if let Some(map_data) =
                section_data.get(sym.st_value as usize..section_data.len() as usize)
            {
                objects.push(Self {
                    definition: MapDefinition::try_from(map_data)?,
                    name,
                    symbol_name,
                });
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_blueprint_object_parsing() {
        let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join(format!("test_program_{}", std::env::consts::ARCH));
        assert!(
            program.exists(),
            "test program object not found: {:?}",
            program
        );

        let data = fs::read(program).unwrap();

        let blueprint = ProgramBlueprint::new(&data, None).unwrap();

        let prog = blueprint.programs.get("test_program_map_update");
        assert!(
            prog.is_some(),
            "expected program 'test_program_map_update' missing"
        );
        let prog = prog.unwrap();
        assert_eq!(
            prog.program_type,
            ProgramType::Kprobe,
            "expected program to be 'kprobe'"
        );
        assert_eq!(
            prog.required_maps(),
            vec!["__test_map".to_string()],
            "expected program to depend on 'test_map'"
        );

        let map = blueprint.maps.get("__test_map");
        assert!(map.is_some(), "expected map 'test_map' missing");
        let map = map.unwrap();
        assert_eq!(map.symbol_name, "__test_map");
        assert_eq!(map.name, "test_map");
    }
}
