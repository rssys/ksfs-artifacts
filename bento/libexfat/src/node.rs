use alloc::string::String;
use alloc::vec::Vec;
pub type Nid = u64;

pub(crate) const NID_NONE: Nid = 0;
pub(crate) const NID_ROOT: Nid = 1;
pub(crate) const NID_NODE_OFFSET: Nid = 2;

#[derive(Debug)]
pub struct Node {
    pub(crate) references: isize,
    pub(crate) fptr_index: u32,
    pub(crate) fptr_cluster: u32,
    pub(crate) entry_offset: u64,
    pub(crate) start_cluster: u32,
    pub(crate) attrib: u16,
    pub(crate) continuations: u8,
    pub(crate) is_contiguous: bool,
    pub(crate) is_cached: bool,
    pub(crate) is_dirty: bool,
    pub(crate) valid_size: u64,
    pub(crate) size: u64,
    pub(crate) mtime: u64,
    pub(crate) atime: u64,
    pub(crate) name: Vec<u16>,
    strname: String,            // Rust
    pub(crate) nid: Nid,        // Rust
    pub(crate) pnid: Nid,       // Rust
    pub(crate) cnids: Vec<Nid>, // Rust
}

impl Node {
    pub(crate) fn new_root() -> Self {
        Self::new(NID_ROOT)
    }

    pub(crate) fn new(nid: Nid) -> Self {
        Self {
            references: 0,
            fptr_index: 0,
            fptr_cluster: 0,
            entry_offset: 0,
            start_cluster: 0,
            attrib: 0,
            continuations: 0,
            is_contiguous: false,
            is_cached: false,
            is_dirty: false,
            valid_size: 0,
            size: 0,
            mtime: 0,
            atime: 0,
            name: vec![],
            strname: String::new(),
            nid,
            pnid: NID_NONE,
            cnids: vec![],
        }
    }

    pub fn get(&mut self) {
        self.references += 1;
    }

    /// # Panics
    pub fn put(&mut self) {
        self.references -= 1;
        if self.references < 0 {
            panic!(
                "reference counter of {} (nid {}) is below zero",
                self.get_name(),
                self.nid
            );
        } else if self.references == 0 && self.nid != NID_ROOT && self.is_dirty {
            panic!(
                "dirty node {} (nid {}) with zero references",
                self.get_name(),
                self.nid
            ); // exfat_warn() in relan/exfat
        }
    }

    #[must_use]
    pub fn get_start_cluster(&self) -> u32 {
        self.start_cluster
    }

    #[must_use]
    pub fn get_attrib(&self) -> u16 {
        self.attrib
    }

    pub fn set_attrib(&mut self, attrib: u16) {
        self.attrib = attrib;
    }

    #[must_use]
    pub fn get_is_contiguous(&self) -> bool {
        self.is_contiguous
    }

    pub fn set_is_dirty(&mut self) {
        self.is_dirty = true;
    }

    #[must_use]
    pub fn get_size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn get_name(&self) -> &str {
        &self.strname
    }

    #[must_use]
    pub fn get_nid(&self) -> Nid {
        self.nid
    }

    #[must_use]
    pub fn get_pnid(&self) -> Nid {
        self.pnid
    }

    #[must_use]
    pub fn is_directory(&self) -> bool {
        (self.attrib & crate::fs::EXFAT_ATTRIB_DIR) != 0
    }

    pub(crate) fn init_meta1(&mut self, meta1: &crate::fs::ExfatEntryMeta1) {
        self.attrib = u16::from_le(meta1.attrib);
        self.continuations = meta1.continuations;
        self.mtime =
            crate::time::exfat2unix(meta1.mdate, meta1.mtime, meta1.mtime_cs, meta1.mtime_tzo);
        // there is no centiseconds field for atime
        self.atime = crate::time::exfat2unix(meta1.adate, meta1.atime, 0, meta1.atime_tzo);
    }

    pub(crate) fn init_meta2(&mut self, meta2: &crate::fs::ExfatEntryMeta2) {
        self.valid_size = u64::from_le(meta2.valid_size);
        self.size = u64::from_le(meta2.size);
        self.start_cluster = u32::from_le(meta2.start_cluster);
        self.fptr_cluster = self.start_cluster;
        self.is_contiguous = (meta2.flags & crate::fs::EXFAT_FLAG_CONTIGUOUS) != 0;
    }

    pub(crate) fn init_name(&mut self, entries: &[crate::fs::ExfatEntry], n: usize) {
        // u16 name
        assert!(self.name.is_empty());
        for entry in entries.iter().take(n) {
            let entry: &crate::fs::ExfatEntryName = bytemuck::cast_ref(entry);
            self.name.extend_from_slice(&entry.name);
        }
        assert_eq!(self.name.len(), crate::fs::EXFAT_ENAME_MAX * n);
        // string name
        let output = crate::utf::utf16_to_utf8(
            &self.name,
            crate::exfat::UTF8_NAME_BUFFER_MAX,
            self.name.len(),
        )
        .unwrap();
        assert!(self.strname.is_empty());
        self.strname = libfs::string::b2s(&output).unwrap();
    }

    pub(crate) fn update_name(&mut self, entries: &[crate::fs::ExfatEntry], n: usize) {
        self.name.clear();
        self.strname.clear();
        self.init_name(entries, n);
    }

    pub(crate) fn update_atime(&mut self) {
        self.atime = libfs::time::get_current().unwrap();
        self.is_dirty = true;
    }

    pub(crate) fn update_mtime(&mut self) {
        self.mtime = libfs::time::get_current().unwrap();
        self.is_dirty = true;
    }

    pub(crate) fn is_valid(&self) -> bool {
        if self.references < 0 {
            return false;
        }
        if self.atime == 0 || self.mtime == 0 {
            return false;
        }
        if self.name.is_empty() || self.name[0] == 0 {
            return false;
        }
        if self.strname.is_empty() {
            return false;
        }
        if self.nid == NID_NONE {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_node_nid() {
        let node = super::Node::new_root();
        assert_eq!(node.nid, super::NID_ROOT);
        assert_eq!(node.pnid, super::NID_NONE);
        assert!(node.cnids.is_empty());
    }

    #[test]
    fn test_node_get_put() {
        let mut node = super::Node::new_root();
        assert_eq!(node.references, 0);
        node.get();
        assert_eq!(node.references, 1);
        node.get();
        assert_eq!(node.references, 2);
        node.put();
        assert_eq!(node.references, 1);
        node.put();
        assert_eq!(node.references, 0);
    }

    #[test]
    fn test_node_get_name() {
        let node = super::Node::new_root();
        assert_eq!(node.get_name(), "");
    }

    #[test]
    fn test_node_update_atime() {
        let mut node = super::Node::new_root();
        assert_eq!(node.atime, 0);
        assert!(!node.is_dirty);

        node.update_atime();
        assert_ne!(node.atime, 0);
        assert!(node.is_dirty);
    }

    #[test]
    fn test_node_update_mtime() {
        let mut node = super::Node::new_root();
        assert_eq!(node.mtime, 0);
        assert!(!node.is_dirty);

        node.update_mtime();
        assert_ne!(node.mtime, 0);
        assert!(node.is_dirty);
    }
}
