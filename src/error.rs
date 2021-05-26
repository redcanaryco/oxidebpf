use nix::errno::Errno;
use std::any::Any;
use std::ffi::NulError;

#[derive(Debug, PartialEq, Clone)]
pub enum OxidebpfError {
    InvalidElf,
    InvalidElfMachine,
    UnknownObject(String),
    LinuxError(Errno),
    PerfEventDoesNotExist,
    PerfIoctlError(nix::Error),
    CStringConversionError(NulError),
}
