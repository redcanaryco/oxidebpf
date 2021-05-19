
pub struct KProbe {

}

pub struct UProbe {

}

pub trait Probe {
    fn new();
    fn name(&self);
}

impl Probe for KProbe {
    fn new() {
        unimplemented!()
    }

    fn name(&self) {
        unimplemented!()
    }
}

impl KProbe {
    fn attach_kprobe(&self) {
        unimplemented!()
    }

    fn detach_kprobe(&self) {
        unimplemented!()
    }
}

impl Probe for UProbe {
    fn new() {
        todo!()
    }

    fn name(&self) {
        todo!()
    }
}

impl UProbe {
    fn attach_uprobe(&self) {
        unimplemented!()
    }

    fn detach_uprobe(&self) {
        unimplemented!()
    }
}

impl Drop for KProbe {
    fn drop(&mut self) {
        todo!()
    }
}

impl Drop for UProbe {
    fn drop(&mut self) {
        todo!()
    }
}