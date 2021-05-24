#[derive(Debug, PartialEq, Clone)]
pub enum EbpfObjectError {
    InvalidElf,
    InvalidElfMachine,
    UnknownObject(String),
}
