use nix::errno::Errno;

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
}
