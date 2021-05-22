#[derive(Debug, PartialEq, Clone)]
pub enum EbpfParserError {
    InvalidElf,
    InvalidElfMachine,
    UnsupportedMap,
    UnsupportedProgram,
}
