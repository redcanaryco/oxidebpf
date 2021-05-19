use std::os::unix::io::RawFd;

pub struct KProbe {
    fd: RawFd,
}

pub struct UProbe {
    fd: RawFd,
}

impl KProbe {
    pub fn new() {
        unimplemented!()
    }

    pub fn name(&self) {
        unimplemented!()
    }

    pub(crate) fn attach_kprobe(&self) {
        unimplemented!()
    }

    pub(crate) fn detach_kprobe(&self) {
        unimplemented!()
    }
}

impl UProbe {
    pub fn new() {
        todo!()
    }

    pub fn name(&self) {
        todo!()
    }

    pub(crate) fn attach_uprobe(&self) {
        unimplemented!()
    }

    pub(crate) fn detach_uprobe(&self) {
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