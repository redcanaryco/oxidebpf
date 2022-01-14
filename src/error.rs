use nix::errno::Errno;
use std::ffi::NulError;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Clone)]
pub enum OxidebpfError {
    /// If you encounter this error, you need to set a `buffer_capacity` with the
    /// `buffer_capacity(usize)` builder function when creating your `ProgramGroup`.
    ChannelCapacityNotSpecified,
    BadPerfSample,
    NoPerfData,
    DebugFsNotMounted,
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
    /// If Errno is EPERM when receiving this error, check that the calling process
    /// has appropriate capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, and CAP_BPF are
    /// typically required) and that the user's memlock limit is high enough to load
    /// your programs. If the memlock limit is too low, this library exposes a
    /// `set_memlock_limit(new_limit)` function which can raise it for you.
    LinuxError(String, Errno),
    PerfEventDoesNotExist,
    PerfIoctlError(nix::Error),
    CStringConversionError(NulError),
    MapNotLoaded,
    ProgramNotFound(String),
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
    RetryError(String),
    LockError,
    /// This error is returned when trying to attach a kretprobe with debugfs.
    /// There's a chance we need to change the path name and retry, which is what
    /// this error indicates.
    KretprobeNamingError,
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

impl From<retry::Error<OxidebpfError>> for OxidebpfError {
    fn from(e: retry::Error<OxidebpfError>) -> Self {
        match e {
            retry::Error::Operation { error, .. } => error,
            retry::Error::Internal(i) => OxidebpfError::RetryError(i),
        }
    }
}

impl From<retry::Error<&str>> for OxidebpfError {
    fn from(e: retry::Error<&str>) -> Self {
        match e {
            retry::Error::Operation { error, .. } => OxidebpfError::RetryError(error.to_string()),
            retry::Error::Internal(i) => OxidebpfError::RetryError(i),
        }
    }
}

pub enum InitError {
    Creation(std::io::Error),
    Registration(std::io::Error),
    ReadySignal(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InitError::Creation(e) => write!(f, "error creating poller: {}", e),
            InitError::Registration(e) => write!(f, "error registering poller: {}", e),
            InitError::ReadySignal(e) => write!(f, "error grabbing cond mutex: {}", e),
        }
    }
}

pub enum RunError {
    Poll(std::io::Error),
    Disconnected,
}
