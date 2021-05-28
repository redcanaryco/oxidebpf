use nix::errno::Errno;
use std::ffi::NulError;

#[derive(Debug, PartialEq, Clone)]
pub enum OxidebpfError {
    InvalidElf,
    InvalidProgramObject,
    InvalidMapObject,
    LinuxError(Errno),
    PerfEventDoesNotExist,
    PerfIoctlError(nix::Error),
    CStringConversionError(NulError),
    MapNotLoaded,
    ProgramNotFound,
    MapNotFound,
    NoProgramVersionLoaded(Vec<OxidebpfError>),
    FileIOError,
    Utf8StringConversionError,
    CpuOnlineFormatError,
}
