use std::marker::PhantomData;
use std::error::Error;

pub struct PerfMap<T> {
    base: Map<T>,
    _t: PhantomData<T>,
}

pub struct ArrayMap<T> {
    base: Map<T>,
    _t: PhantomData<T>,
}

pub struct Map<T> {
    _t: PhantomData<T>,
}

pub trait RWMap<T> {
    fn read() -> Result<T, Box<dyn Error>>;
    fn write() -> Result<(), Box<dyn Error>>;
}

impl<T> PerfMap<T> {
    pub fn new() -> PerfMap<T> {
    // add the loop-handler as an arg here, have perfmap spin up thread to handle
    // events?
    unimplemented!()
    }

    pub fn bind() {
    unimplemented!()
    }
}

impl<T> RWMap<T> for PerfMap<T> {
    fn read() -> Result<T, Box<dyn Error>> {
        unimplemented!()
    }

    fn write() -> Result<(), Box<dyn Error>>{
        unimplemented!()
    }
}

impl<T> ArrayMap<T> {
    pub fn new() -> ArrayMap<T> {
        unimplemented!()
    }
}

impl<T> RWMap<T> for ArrayMap<T> {
    fn read() -> Result<T, Box<dyn Error>> {
        unimplemented!()
    }

    fn write() -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}

impl<T> Drop for PerfMap<T> {
    fn drop(&mut self) {
        todo!()
    }
}

impl<T> Drop for ArrayMap<T> {
    fn drop(&mut self) {
        todo!()
    }
}
