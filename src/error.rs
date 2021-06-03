use nix::errno::Errno;
use std::ffi::NulError;

#[derive(Debug, PartialEq, Clone)]
pub enum OxidebpfError {
    SelfTrace,
    UnsupportedProgramType,
    ProgramNotLoaded,
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
    BadPageSize,
    BadPageCount,
    UnsupportedEventType,
    MultipleErrors(Vec<OxidebpfError>),
    UncaughtMountNsError,
}

impl std::fmt::Display for OxidebpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<Vec<OxidebpfError>> for OxidebpfError {
    fn from(e: Vec<OxidebpfError>) -> Self {
        Self::MultipleErrors(e)
    }
}
