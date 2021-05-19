use std::marker::PhantomData;

pub struct Map {

}

pub struct PerfMap<T> {
    base: Map,
    _t: PhantomData<T>,
}

pub struct ArrayMap<T> {
    base: Map,
    _t: PhantomData<T>,
}

impl Map {

}

impl<T> PerfMap<T> {
    pub fn bind() {
        unimplemented!()
    }

    pub fn read() -> T {
        unimplemented!()
    }

    pub fn write() {
        unimplemented!()
    }
}

impl<T> ArrayMap<T> {
    pub fn read() -> T {
        unimplemented!()
    }

    pub fn write() {
        unimplemented!()
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        todo!()
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