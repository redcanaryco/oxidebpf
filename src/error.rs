use nix::errno::Errno;
use std::ffi::NulError;

#[derive(Debug, PartialEq, Clone)]
pub enum EbpfObjectError {
    InvalidElf,
    InvalidElfMachine,
    UnknownObject(String),
}

#[derive(Debug, PartialEq, Clone)]
pub enum EbpfSyscallError {
    LinuxError(Errno),
    PerfEventDoesNotExist,
    PerfIoctlError(nix::Error),
    CStringConversionError(NulError),
}

#[derive(Debug, PartialEq, Clone)]
pub enum EbpfParserError {
    InvalidElf,
}

impl From<EbpfParserError> for EbpfObjectError {
    fn from(e: EbpfParserError) -> Self {
        match e {
            EbpfParserError::InvalidElf => EbpfObjectError::InvalidElf,
        }
    }
}
