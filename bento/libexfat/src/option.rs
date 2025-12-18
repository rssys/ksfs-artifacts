#[derive(Clone, Copy, Debug)]
pub enum OpenMode {
    Rw,
    Ro,
    Any,
}

#[derive(Debug)]
pub enum RepairMode {
    Yes,
    No,
}

#[derive(Debug)]
pub enum NidAllocMode {
    Linear,
    Bitmap,
}

#[derive(Debug)]
pub struct Opt {
    pub mode: OpenMode,
    pub repair: RepairMode,
    pub noatime: bool,
    pub dmask: crate::exfat::StatMode,
    pub fmask: crate::exfat::StatMode,
    pub uid: u32,
    pub gid: u32,
    pub nidalloc: NidAllocMode,
    pub debug: bool,
}
