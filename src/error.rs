use nix::errno::Errno;
use std::ffi::NulError;
use std::fmt::Display;

#[derive(Debug, PartialEq, Clone)]
pub enum OxidebpfError {
    BadPerfSample,
    NoPerfData,
    EbpfPollerError(String),
    CStrConversionError,
    ThreadPollingError,
    UuidError,
    NumberParserError,
    SelfTrace,
    UnsupportedProgramType,
    ProgramNotLoaded,
    InvalidElf,
    InvalidProgramLength,
    InvalidInstructionLength,
    KernelVersionNotFound,
    MissingRelocationSection(u32),
    InvalidMapObject,
    LinuxError(String, Errno),
    PerfEventDoesNotExist,
    PerfIoctlError(nix::Error),
    CStringConversionError(NulError),
    MapNotLoaded,
    ProgramNotFound,
    MapNotFound(String),
    NoProgramVersionLoaded(Vec<OxidebpfError>),
    FileIOError,
    Utf8StringConversionError,
    CpuOnlineFormatError,
    BadPageSize,
    BadPageCount,
    UnsupportedEventType,
    MultipleErrors(Vec<OxidebpfError>),
    UncaughtMountNsError,
    BpfProgLoadError((Box<OxidebpfError>, String)),
    MapKeyNotFound,
    MapValueSizeMismatch,
    MapKeySizeMismatch,
    ProgramGroupAlreadyLoaded,
}

impl Display for OxidebpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OxidebpfError::NoProgramVersionLoaded(e) => {
                for err in e {
                    match err {
                        OxidebpfError::BpfProgLoadError(e) => {
                            if let Err(e) = write!(f, "{}", &e.1) {
                                return Err(e);
                            };
                        }
                        _ => {
                            if let Err(e) = write!(f, "{:?}", err) {
                                return Err(e);
                            };
                        }
                    }
                }
                Ok(())
            }
            _ => {
                write!(f, "{:?}", self)
            }
        }
    }
}

impl From<Vec<OxidebpfError>> for OxidebpfError {
    fn from(e: Vec<OxidebpfError>) -> Self {
        Self::MultipleErrors(e)
    }
}
