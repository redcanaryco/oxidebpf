pub mod maps;
pub mod probes;

pub struct Module {

}

pub enum Program {

}

pub struct ProgramData {

}

pub enum Event {

}

impl Module {
    pub fn parse() -> Module {
        unimplemented!()
    }
}

impl Program {
    pub fn new() -> Program {
        unimplemented!()
    }

    pub fn data() {
        unimplemented!()
    }

    pub fn data_mut() {
        unimplemented!()
    }

    pub fn load() {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
