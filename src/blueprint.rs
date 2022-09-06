use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::os::unix::io::RawFd;

use crate::LOGGER;
use slog::{debug, info};

use goblin::elf::{header, section_header, Elf, SectionHeader, Sym};
use itertools::Itertools;

use crate::bpf::*;
use crate::error::*;
use crate::set_memlock_limit;
use crate::ProgramType;

/// Structure that parses eBPF objects from an ELF object.
#[derive(Debug, Clone, Default)]
pub struct ProgramBlueprint {
    pub(crate) maps: HashMap<String, MapObject>,
    pub(crate) programs: HashMap<String, ProgramObject>,
}

/// Enum which describes how the blueprint will parse sections not covered in our eBPF ABI.
#[derive(Debug, Clone)]
pub enum SectionType<'a> {
    Map {
        /// The name of the section prefix.
        section_prefix: &'a str,
    },
    Program {
        /// The name of the section prefix.
        section_prefix: &'a str,
        /// The type of program.
        program_type: ProgramType,
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
    /// Create a new `ProgramBlueprint` from a given series of bytes.
    ///
    /// The bytes can come from any source, but the easiest way is to load them directly
    /// from a file. See the included examples below. The program assumes a default ABI for
    /// specifying probes and maps by section name, as used in the
    /// [redcanary-ebpf-sensor](https://github.com/redcanaryco/redcanary-ebpf-sensor).
    ///
    /// # Default ABI
    ///
    /// The default ABI assumes that probes are in their own section with the name
    /// `<probe type>/<probe name>` (e.g., `kprobe/sys_process_vm_writev`). Maps
    /// are also assumed to be prefixed with `maps`, followed by the map name (e.g.,
    /// `maps/wpm_events`). It is common in many eBPF examples for maps to all
    /// be placed in the same section, simply called `maps`. If this is the case, you will
    /// need to provide your own custom section parser (see below examples).
    ///
    /// Here is a snippet of what a default eBPF program might look like.
    ///
    /// ```C
    /// struct bpf_map_def SEC("maps/wpm_events") write_process_memory_events = {
    ///     // map configuration goes here
    /// };
    ///
    /// SEC("kprobe/sys_ptrace_write")
    /// int kprobe__sys_ptrace_write(struct pt_regs *__ctx)
    /// {
    ///     // probe configuration goes here
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// This example creates a new `ProgramBlueprint` with the default section parser.
    ///
    /// ```
    /// use std::path::PathBuf;
    /// use oxidebpf::ProgramBlueprint;
    /// use std::fs;
    ///
    /// ProgramBlueprint::new(
    ///     fs::read(
    ///         PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    ///         .join("test")
    ///         .join(format!("test_program_{}", std::env::consts::ARCH)),
    ///     )
    ///     .unwrap()
    ///     .as_slice(),
    ///     None,
    /// )
    /// .unwrap();
    ///
    /// ```
    ///
    /// This example creates a new `ProgramBlueprint` with a custom section parser.
    ///
    /// ```ignore
    /// use std::path::PathBuf;
    /// use oxidebpf::blueprint::{ProgramBlueprint, SectionType};
    /// use oxidebpf::ProgramType;
    /// use std::fs;
    ///
    /// let program_bytes = fs::read(
    ///         // your program here
    ///     )
    ///     .unwrap()
    ///     .as_slice();
    ///
    /// let section_types = vec![
    ///     SectionType::Map { section_prefix: "mymap" },
    ///     SectionType::Program {
    ///         section_prefix: "probes",
    ///         program_type: ProgramType::Kprobe,
    ///     },
    /// ];
    ///
    /// let program_blueprint = ProgramBlueprint::new(&program_bytes, Some(section_types))?;
    /// ```
    ///
    /// The `test.o` program loaded by this custom parser might look like this:
    ///
    /// ```c
    /// struct bpf_map_def SEC("mymap") my_map = {
    ///     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    ///     .key_size = sizeof(u32),
    ///     .value_size = sizeof(u32),
    ///     .max_entries = 1024,
    ///     .pinning = 0,
    ///     .namespace = "",
    /// };
    ///
    /// SEC("probes/sys_setuid")
    /// int kprobe__sys_setuid(struct pt_regs *regs)
    /// {
    ///     return 0;
    /// }
    /// ```
    ///
    pub fn new(
        data: &[u8],
        section_types: Option<Vec<SectionType>>,
    ) -> Result<Self, OxidebpfError> {
        let elf: Elf = parse_and_verify_elf(data)?;
        let mut blueprint = Self::default();
        let kernel_version = get_kernel_version(data, &elf)?;

        debug!(
            LOGGER.0,
            "ProgramBlueprint::new(); Found kernel version: {}", kernel_version
        );

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
                    let program_type = prefix.into();
                    let obj = ProgramObject::from_section(
                        &program_type,
                        name,
                        data,
                        &elf,
                        sh_index,
                        sh,
                        kernel_version,
                    )?;
                    blueprint.programs.insert(obj.name.clone(), obj);
                    continue;
                }
                _ => (),
            }

            // check to see if the section matches up with the section definitions the user passed in
            for section_type in section_types
                .iter()
                .flatten()
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
                            program_type,
                            name,
                            data,
                            &elf,
                            sh_index,
                            sh,
                            kernel_version,
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
    pub kernel_version: u32,
}

impl ProgramObject {
    fn from_section<'a>(
        program_type: &ProgramType,
        name: Option<&str>,
        data: &'a [u8],
        elf: &'a Elf,
        sh_index: usize,
        sh: &'a SectionHeader,
        kernel_version: u32,
    ) -> Result<Self, OxidebpfError> {
        let section_data = get_section_data(data, sh).ok_or_else(|| {
            info!(
                LOGGER.0, "from_section(); Invalid ELF; program_type: {:?}; name: {:?}; data: {:?}; elf: {:?}, sh_index: {:?}; sh: {:?}, kernel_version: {}",
                program_type,
                name,
                data,
                elf,
                sh_index,
                sh,
                kernel_version
            );
            OxidebpfError::InvalidElf
        })?;
        let code = BpfCode::try_from(section_data)?;

        let symbol_name = elf
            .syms
            .iter()
            .find(|sym| sym.st_shndx == sh_index)
            .and_then(|sym| get_symbol_name(elf, &sym))
            .unwrap_or_default();

        // For object naming, we prioritize the section name over the symbol name
        Ok(Self {
            program_type: *program_type,
            name: name.map(str::to_string).unwrap_or(symbol_name),
            code,
            relocations: Reloc::get_map_relocations(sh_index, elf)?,
            license: get_license(data, elf),
            kernel_version,
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
        for reloc in self
            .relocations
            .iter()
            .filter(|r| r.symbol_name == map.symbol_name)
        {
            if let Some(insn) = self.code.0.get_mut(reloc.insn_index as usize) {
                insn.set_src(1);
                insn.imm = fd as i32;
            }
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
        let reloc_index = match reloc_index {
            None => return Ok(Vec::new()),
            Some(r) => r,
        };

        // retrieve the relocation section
        let reloc_section = elf
            .shdr_relocs
            .iter()
            .find(|(index, _relocs)| *index == reloc_index)
            .map(|(_index, relocs)| relocs)
            .ok_or(OxidebpfError::MissingRelocationSection(reloc_index as u32))?;

        Ok(reloc_section
            .iter()
            .filter_map(|r| {
                elf.syms.get(r.r_sym).map(|sym| Reloc {
                    symbol_name: get_symbol_name(elf, &sym).unwrap_or_default(),
                    insn_index: r.r_offset / std::mem::size_of::<BpfInsn>() as u64,
                    reloc_type: r.r_type,
                })
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
    /// The file descriptor of the map, if it's been loaded
    fd: Option<RawFd>,
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
        let mut symbols: Vec<Sym> = elf
            .syms
            .iter()
            .filter(|sym| sym.st_shndx == sh_index)
            .collect();

        // sort symbols by section offsets so we can easily calculate symbol sizes
        symbols.sort_by(|a, b| a.st_value.cmp(&b.st_value));

        for (index, sym) in symbols.iter().enumerate() {
            let symbol_name = get_symbol_name(elf, sym).unwrap_or_default();
            // If a section name was provided (which does not include the "maps/" prefix)
            // then we use that. Otherwise we use the symbol name.
            let name = section_name
                .map(str::to_string)
                .unwrap_or_else(|| symbol_name.clone());

            let upper_bound = if let Some(next_sym) = symbols.get(index + 1) {
                next_sym.st_value as usize
            } else {
                section_data.len()
            };

            if let Some(map_data) = section_data.get(sym.st_value as usize..upper_bound) {
                objects.push(Self {
                    definition: MapDefinition::try_from(map_data)?,
                    name,
                    symbol_name,
                    fd: None,
                });
            }
        }

        Ok(objects)
    }

    pub(crate) fn set_loaded(&mut self, fd: RawFd) {
        self.fd = Some(fd);
    }
    pub(crate) fn get_fd(&self) -> Result<RawFd, OxidebpfError> {
        self.fd.ok_or(OxidebpfError::MapNotLoaded)
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
        .and_then(|section_data| CStr::from_bytes_with_nul(section_data).ok())
        .and_then(|s| s.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn get_kernel_version(data: &[u8], elf: &Elf) -> Result<u32, OxidebpfError> {
    const MAGIC_VERSION: u32 = 0xFFFFFFFE;
    let version = get_section_by_name(elf, "version")
        .and_then(|section| get_section_data(data, section))
        .filter(|section_data| section_data.len() == 4)
        .map(|section_data| {
            let mut int_data: [u8; 4] = Default::default();
            int_data.copy_from_slice(section_data);
            u32::from_ne_bytes(int_data)
        })
        .unwrap_or(MAGIC_VERSION);

    Ok(if version == MAGIC_VERSION {
        #[cfg(not(feature = "rootless_blueprints"))]
        {
            info!(LOGGER.0, "Dynamically finding the running kernel version");
            get_running_kernel_version()?
        }
        #[cfg(feature = "rootless_blueprints")]
        {
            info!(
                LOGGER.0,
                "Rootless blueprints enabled, defaulting to {}. Programs may not load properly.",
                MAGIC_VERSION
            );

            version
        }
    } else {
        version
    })
}

fn get_symbol_name(elf: &Elf, sym: &Sym) -> Option<String> {
    elf.strtab.get_at(sym.st_name).map(String::from)
}

fn parse_and_verify_elf(data: &[u8]) -> Result<Elf, OxidebpfError> {
    let elf = Elf::parse(data).map_err(|e| {
        info!(
            LOGGER.0,
            "parse_and_verify_elf(); Invalid ELF; error: {:?}", e
        );
        OxidebpfError::InvalidElf
    })?;

    match elf.header.e_machine {
        header::EM_BPF | header::EM_NONE => (),
        _ => return Err(OxidebpfError::InvalidElf),
    }

    Ok(elf)
}
fn kernel_major_minor_str_to_u32(release: &str) -> u32 {
    let release = release.to_string();
    // The release information comes in the format "major.minor.patch-extra".
    let mut split = release.split('.').flat_map(str::parse);
    ((split.next().unwrap_or(0) & 0xFF) << 16) + ((split.next().unwrap_or(0) & 0xFF) << 8)
}

// Packs the kernel version into an u32
fn get_running_kernel_version() -> Result<u32, OxidebpfError> {
    let utsname = nix::sys::utsname::uname();
    let release = utsname.release();
    let version_base = kernel_major_minor_str_to_u32(release);

    if let Err(e) = set_memlock_limit(libc::RLIM_INFINITY as usize) {
        info!(
            LOGGER.0,
            "get_running_kernel_version(); failed to set memlock_limit; error: {:?}", e,
        );
    }

    // There doesn't seem a portable way to find the "LINUX_VERSION_CODE", so we create a minimal
    // ebpf program and load it with different versions until we find one that works. At most, we
    // do this 255 times, as we only enumerate the revision number (1 byte).
    let data: Vec<u8> = vec![0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let code = BpfCode::try_from(&data[..])?; // r0 = 0, return r0
    let license = "Proprietary".to_string();
    for revision in 0..256 {
        if let Ok(fd) = crate::bpf::syscall::bpf_prog_load(
            u32::from(&ProgramType::Kprobe),
            &code,
            license.clone(),
            version_base + revision,
        ) {
            unsafe {
                libc::close(fd);
            }
            return Ok(version_base + revision);
        }
    }

    Err(OxidebpfError::KernelVersionNotFound)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::bpf::constant::bpf_map_type;

    #[test]
    fn test_find_running_kernel_version() {
        assert!(get_running_kernel_version().is_ok())
    }

    #[test]
    fn test_kernel_version_parsing() {
        assert_eq!(kernel_major_minor_str_to_u32("4.4.1"), 0x040400);
        assert_eq!(kernel_major_minor_str_to_u32("4.4"), 0x040400);
        assert_eq!(kernel_major_minor_str_to_u32("5.0.0-1234"), 0x050000);
    }

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

        let blueprint = ProgramBlueprint::new(&data, None).expect("blueprint parsing unsuccessful");

        let prog = blueprint
            .programs
            .get("test_program_map_update")
            .expect("expecting 'test_program_map_updates' program to exist");
        assert_eq!(
            prog.program_type,
            ProgramType::Kprobe,
            "expected program to be 'kprobe'"
        );
        assert_eq!(
            prog.required_maps(),
            vec!["__test_map".to_string(), "__test_hash_map".to_string()],
            "expected program to depend on 'test_map'"
        );

        let map = blueprint
            .maps
            .get("__test_map")
            .expect("expecting '__test_map' to exist");
        assert_eq!(map.symbol_name, "__test_map");
        assert_eq!(map.name, "test_map");

        let map = blueprint
            .maps
            .get("__map_combined_section1")
            .expect("expecting '__map_combined_section1' to exist");
        assert_eq!(map.symbol_name, "__map_combined_section1");
        assert_eq!(map.name, "__map_combined_section1");
        assert_eq!(map.definition.map_type, bpf_map_type::BPF_MAP_TYPE_ARRAY);
        assert_eq!(map.definition.key_size, 4);
        assert_eq!(map.definition.value_size, 8);
        assert_eq!(map.definition.max_entries, 1024);

        let map = blueprint
            .maps
            .get("__map_combined_section2")
            .expect("expecting '__map_combined_section2' to exist");
        assert_eq!(map.symbol_name, "__map_combined_section2");
        assert_eq!(map.name, "__map_combined_section2");
        assert_eq!(map.definition.map_type, bpf_map_type::BPF_MAP_TYPE_ARRAY);
        assert_eq!(map.definition.key_size, 4);
        assert_eq!(map.definition.value_size, 12);
        assert_eq!(map.definition.max_entries, 1024);

        let map = blueprint
            .maps
            .get("__test_hash_map")
            .expect("expecting '__test_hash_map' to exist");
        assert_eq!(map.symbol_name, "__test_hash_map");
        assert_eq!(map.name, "test_hash_map");
        assert_eq!(map.definition.map_type, bpf_map_type::BPF_MAP_TYPE_HASH);
        assert_eq!(map.definition.key_size, 8);
        assert_eq!(map.definition.value_size, 8);
        assert_eq!(map.definition.max_entries, 1024);
    }
}
