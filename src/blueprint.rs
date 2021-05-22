use goblin::elf::{header, section_header, Elf, SectionHeader};
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong};

use crate::bpf::*;
use crate::error::*;
use crate::sys::get_kernel_version;

/// Structure that parses and holds eBPF objects from an ELF object.
#[derive(Default)]
pub struct ProgramBlueprint {
    maps: Vec<MapObject>,
    programs: Vec<ProgramObject>,
}

///@TODO: This will need to be merged with the struct in lib.rs
#[derive(Clone)]
pub(crate) struct ProgramObject {
    pub ptype: ObjectProgramType,
    pub name: String,
    pub instructions: BpfCode,
    pub license: String,
    pub version: u32,
}

///@TODO: This will need to be merged with the struct in lib.rs
#[derive(Clone)]
pub(crate) struct MapObject {
    pub definition: BpfMapDef,
    pub name: String,
    pub init_data: Option<Vec<u8>>,
}

impl MapObject {
    fn requires_initialization(&self) -> bool {
        self.init_data.is_some()
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

fn program_section_filter(
    data: &[u8],
    elf: &Elf,
    sh: &SectionHeader,
    license: String,
    version: u32,
) -> Option<ProgramObject> {
    if sh.sh_type != section_header::SHT_PROGBITS || sh.sh_size == 0 {
        return None;
    }

    let section_name = match get_section_name(elf, sh) {
        None => { return None }
        Some(s) => { s }
    }.to_string();

    let mut name_split = section_name.splitn(1, '/');
    let first = name_split.next().unwrap_or_default();

    // @TODO: this looks incomplete?
    None
}

fn map_section_filter(data: &[u8], elf: &Elf, sh: &SectionHeader) -> Option<MapObject> {
    if sh.sh_type != section_header::SHT_PROGBITS || sh.sh_size == 0 {
        return None;
    }
    let section_name = match get_section_name(elf, sh) {
        None => { return None }
        Some(s) => { s }
    }.to_string();
    let mut name_split = section_name.splitn(1, '/');
    let first = name_split.next().unwrap_or_default();

    match ObjectMapType::try_from(first).ok()? {
        ObjectMapType::Map => {
            let name = name_split.next().unwrap_or_default().to_string();
            let definition = BpfMapDef::try_from(get_section_data(data, sh)).ok()?;
            Some(MapObject {
                name,
                definition,
                init_data: None,
            })
        }
        ObjectMapType::Data
        | ObjectMapType::RoData
        | ObjectMapType::Unspec
        | ObjectMapType::Bss => None,
    }
}

fn parse_and_verify_elf(data: &[u8]) -> Result<Elf, EbpfParserError> {
    let elf = Elf::parse(data).map_err(|_e| EbpfParserError::InvalidElf)?;

    match elf.header.e_machine {
        header::EM_BPF | header::EM_NONE => (),
        val => return Err(EbpfParserError::InvalidElfMachine),
    }

    Ok(elf)
}

impl ProgramBlueprint {
    pub fn new(data: &[u8]) -> Result<Self, EbpfParserError> {
        let elf: Elf = parse_and_verify_elf(data)?;

        let mut blueprint = Self::default();

        let license = get_license(data, &elf);
        let version = get_version(data, &elf);

        // create map objects
        elf.section_headers
            .iter()
            .filter_map(|sh| map_section_filter(data, &elf, sh))
            .for_each(|map_object| {
                blueprint.maps.push(map_object);
            });

        // create program objects
        // @TODO: double check this license.clone()
        elf.section_headers
            .iter()
            .filter_map(|sh| program_section_filter(data, &elf, sh, license.clone(), version))
            .for_each(|prog_object| {
                blueprint.programs.push(prog_object);
            });

        Ok(blueprint)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
