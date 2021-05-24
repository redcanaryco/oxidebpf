use nix::errno::Errno;

#[derive(Debug, PartialEq, Clone)]
pub enum EbpfParserError {
    InvalidElf,
    InvalidElfMachine,
    UnsupportedMap,
    UnsupportedProgram,
}

#[derive(Debug, PartialEq, Clone)]
pub enum EbpfSyscallError {
    LinuxError(Errno),
    PerfEventDoesNotExist,
}
