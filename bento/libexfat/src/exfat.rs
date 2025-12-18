use bento::std as std;
use byteorder::ByteOrder;
use std::io::Write;
use bento::libc::*;
use bento::kernel::stat::*;
use alloc::vec::Vec;
use alloc::string::String;
use hashbrown::HashMap;
use bento::println;
use crate::device::{AsyncRead, AsyncWrite};

macro_rules! get_node {
    ($ef:expr, $nid:expr) => {
        $ef.nmap.get($nid).unwrap()
    };
}
pub(crate) use get_node;

macro_rules! get_node_mut {
    ($ef:expr, $nid:expr) => {
        $ef.nmap.get_mut($nid).unwrap()
    };
}
pub(crate) use get_node_mut;

const NAME_MAX: usize = 255;

// UTF-16 encodes code points up to U+FFFF as single 16-bit code units.
// UTF-8 uses up to 3 bytes (i.e. 8-bit code units) to encode code points
// up to U+FFFF. relan/exfat has +1 for NULL termination.
pub(crate) const UTF8_NAME_BUFFER_MAX: usize = NAME_MAX * 3;
pub(crate) const UTF8_ENAME_BUFFER_MAX: usize = crate::fs::EXFAT_ENAME_MAX * 3;

#[cfg(target_os = "linux")]
pub type StatMode = u32;
#[cfg(not(target_os = "linux"))] // FreeBSD
pub type StatMode = u16;

pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u32,
    pub st_mode: StatMode,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u32,
    pub st_size: u64,
    pub st_blksize: u32,
    pub st_blocks: u64,
    pub st_atime: u64,
    pub st_mtime: u64,
    pub st_ctime: u64,
}

pub struct StatFs {
    pub f_bsize: u32,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namelen: u32,
    pub f_frsize: u32,
}

pub struct Cursor {
    pnid: crate::node::Nid,
    curnid: crate::node::Nid,
    curidx: usize,
}

impl Cursor {
    fn new(pnid: crate::node::Nid) -> Self {
        Self {
            pnid,
            curnid: crate::node::NID_NONE,
            curidx: usize::MAX,
        }
    }
}

#[derive(Default)]
pub(crate) struct ClusterMap {
    start_cluster: u32,
    pub(crate) count: u32,
    pub(crate) chunk: libfs::bitmap::Bitmap,
    dirty: bool,
}

impl ClusterMap {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub(crate) struct NidMap {
    pub(crate) next: crate::node::Nid,
    pub(crate) max: crate::node::Nid,
    pub(crate) pool: Vec<crate::node::Nid>,
    pub(crate) chunk: libfs::bitmap::Bitmap,
}

impl NidMap {
    fn new() -> Self {
        Self {
            next: crate::node::NID_NODE_OFFSET,
            ..Default::default()
        }
    }
}

pub struct Exfat {
    pub(crate) opt: crate::option::Opt, // Rust
    pub(crate) dev: crate::device::Device,
    pub(crate) sb: crate::fs::ExfatSuperBlock,
    upcase: Vec<u16>,
    pub(crate) cmap: ClusterMap,
    pub(crate) strlabel: String,
    zero_cluster: Vec<u8>,
    pub(crate) ro: isize,
    pub(crate) errors: usize,       // global variable in relan/exfat
    pub(crate) errors_fixed: usize, // global variable in relan/exfat
    pub(crate) imap: NidMap,        // Rust
    pub(crate) nmap: HashMap<crate::node::Nid, crate::node::Node>, // Rust
}

impl Drop for Exfat {
    fn drop(&mut self) {
        if !self.nmap.is_empty() {
            assert!(self.nmap.contains_key(&crate::node::NID_ROOT));
            self.unmount().unwrap();
        }
    }
}

impl Exfat {
    fn new(dev: crate::device::Device, opt: crate::option::Opt) -> Self {
        Self {
            opt,
            dev,
            sb: crate::fs::ExfatSuperBlock::new(),
            upcase: vec![],
            cmap: ClusterMap::new(),
            strlabel: String::new(),
            zero_cluster: vec![],
            ro: 0,
            errors: 0,
            errors_fixed: 0,
            imap: NidMap::new(),
            nmap: HashMap::new(),
        }
    }

    // Sector to absolute offset.
    fn s2o(&self, sector: u64) -> u64 {
        sector << self.sb.sector_bits
    }

    // Cluster to sector.
    fn c2s(&self, cluster: u32) -> u64 {
        assert!(
            cluster >= crate::fs::EXFAT_FIRST_DATA_CLUSTER,
            "invalid cluster number {cluster}"
        );
        u64::from(u32::from_le(self.sb.cluster_sector_start))
            + (u64::from(cluster - crate::fs::EXFAT_FIRST_DATA_CLUSTER) << self.sb.spc_bits)
    }

    // Cluster to absolute offset.
    #[must_use]
    pub fn c2o(&self, cluster: u32) -> u64 {
        self.s2o(self.c2s(cluster))
    }

    // Sector to cluster.
    fn s2c(&self, sector: u64) -> crate::Result<u32> {
        // dumpexfat (the only user of this fn) initially passes zero,
        // and relan/exfat returns a negative cluster in uint32_t.
        // It's a bug, but usually works as the value exceeds max clusters.
        // In Rust, do extra sanity to prevent u32::try_from failure.
        let cluster_sector_start = u32::from_le(self.sb.cluster_sector_start).into();
        if sector < cluster_sector_start {
            return Ok(u32::MAX);
        }
        match u32::try_from((sector - cluster_sector_start) >> self.sb.spc_bits) {
            Ok(v) => Ok(v + crate::fs::EXFAT_FIRST_DATA_CLUSTER),
            Err(e) => {
                println!("{e}");
                Err(crate::Error::Errno(EINVAL))
            }
        }
    }

    // Size in bytes to size in clusters (rounded upwards).
    fn bytes2clusters(&self, bytes: u64) -> crate::Result<u32> {
        match crate::util::div_round_up!(bytes, self.get_cluster_size()).try_into() {
            Ok(v) => Ok(v),
            Err(e) => {
                println!("{e}");
                Err(crate::Error::Errno(EFBIG)) // pjdfstest/tests/ftruncate/12.t
            }
        }
    }

    #[must_use]
    pub fn cluster_invalid(&self, c: u32) -> bool {
        c < crate::fs::EXFAT_FIRST_DATA_CLUSTER
            || c - crate::fs::EXFAT_FIRST_DATA_CLUSTER >= u32::from_le(self.sb.cluster_count)
    }

    /// # Panics
    pub fn next_cluster(&mut self, nid: crate::node::Nid, cluster: u32) -> u32 {
        assert!(
            cluster >= crate::fs::EXFAT_FIRST_DATA_CLUSTER,
            "bad cluster {cluster:#x}"
        );
        if get_node!(self, &nid).is_contiguous {
            return cluster + 1;
        }
        let fat_offset = self.s2o(u32::from_le(self.sb.fat_sector_start).into())
            + u64::from(cluster) * crate::fs::EXFAT_CLUSTER_SIZE_U64;
        let next = match self
            .dev
            .preadx(crate::fs::EXFAT_CLUSTER_SIZE_U64, fat_offset)
        {
            Ok(v) => v,
            Err(e) => {
                return crate::fs::EXFAT_CLUSTER_BAD;
            }
        };
        u32::from_le_bytes(next.try_into().unwrap())
    }

    fn advance_cluster(&mut self, nid: crate::node::Nid, count: u32) -> crate::Result<u32> {
        let node = get_node_mut!(self, &nid);
        if node.is_contiguous {
            node.fptr_index = count;
            node.fptr_cluster = node.start_cluster + count;
            return Ok(node.fptr_cluster);
        }
        if node.fptr_index > count {
            node.fptr_index = 0;
            node.fptr_cluster = node.start_cluster;
        }
        for _ in node.fptr_index..count {
            let node_fptr_cluster = self.next_cluster(nid, get_node!(self, &nid).fptr_cluster);
            get_node_mut!(self, &nid).fptr_cluster = node_fptr_cluster;
            if self.cluster_invalid(node_fptr_cluster) {
                println!("invalid cluster {node_fptr_cluster:#x}");
                return Err(crate::Error::Errno(EIO));
            }
        }
        let node = get_node_mut!(self, &nid);
        node.fptr_index = count;
        Ok(node.fptr_cluster)
    }

    /// # Errors
    pub fn flush_nodes(&mut self) -> crate::Result<()> {
        self.flush_nodes_impl(crate::node::NID_ROOT)
    }

    fn flush_nodes_impl(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        let n = get_node!(self, &nid).cnids.len();
        let mut i = 0; // index access to prevent cnids.clone()
        while i < n {
            let cnid = get_node!(self, &nid).cnids[i];
            self.flush_nodes_impl(cnid)?;
            i += 1;
        }
        self.flush_node(nid)
    }

    /// # Errors
    pub fn flush(&mut self) -> crate::Result<()> {
        if self.cmap.dirty {
            let offset = self.c2o(self.cmap.start_cluster);
            if let Err(e) = self.dev.pwrite(self.cmap.chunk.as_bytes(), offset) {
                println!("failed to write clusters bitmap");
                return Err(e.into());
            }
            self.cmap.dirty = false;
        }
        Ok(())
    }

    fn set_next_cluster(
        &mut self,
        contiguous: bool,
        current: u32,
        next: u32,
    ) -> std::io::Result<()> {
        if contiguous {
            return Ok(());
        }
        let fat_offset = self.s2o(u32::from_le(self.sb.fat_sector_start).into())
            + u64::from(current) * crate::fs::EXFAT_CLUSTER_SIZE_U64;
        if let Err(e) = self.dev.pwrite(&next.to_le().to_ne_bytes(), fat_offset) {
            return Err(e);
        }
        Ok(())
    }

    fn allocate_cluster(&mut self, hint: u32) -> crate::Result<u32> {
        let mut hint = hint;
        if hint < crate::fs::EXFAT_FIRST_DATA_CLUSTER {
            hint = 0;
        } else {
            hint -= crate::fs::EXFAT_FIRST_DATA_CLUSTER;
            if hint >= self.cmap.count {
                hint = 0;
            }
        }
        let cluster = match self.ffas_cluster(hint, self.cmap.count) {
            Ok(v) => v,
            Err(crate::Error::Errno(ENOSPC)) => match self.ffas_cluster(0, hint) {
                Ok(v) => v,
                Err(crate::Error::Errno(ENOSPC)) => {
                    println!("no free space left for cluster");
                    return Err(crate::Error::Errno(ENOSPC));
                }
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        self.cmap.dirty = true;
        Ok(cluster)
    }

    fn free_cluster(&mut self, cluster: u32) -> crate::Result<()> {
        assert!(
            cluster - crate::fs::EXFAT_FIRST_DATA_CLUSTER < self.cmap.count,
            "caller must check cluster validity ({:#x},{:#x})",
            cluster,
            self.cmap.count
        );
        self.cmap.chunk.clear(
            (cluster - crate::fs::EXFAT_FIRST_DATA_CLUSTER)
                .try_into()
                .unwrap(),
        )?;
        self.cmap.dirty = true;
        Ok(())
    }

    fn make_noncontiguous(&mut self, first: u32, last: u32) -> std::io::Result<()> {
        for c in first..last {
            self.set_next_cluster(false, c, c + 1)?;
        }
        Ok(())
    }

    fn grow_file(
        &mut self,
        nid: crate::node::Nid,
        current: u32,
        difference: u32,
    ) -> crate::Result<()> {
        assert_ne!(difference, 0, "zero difference passed");
        let mut previous;
        let mut allocated = 0;
        let node = get_node!(self, &nid);

        if node.start_cluster == crate::fs::EXFAT_CLUSTER_FREE {
            assert_eq!(
                node.fptr_index, 0,
                "non-zero pointer index {}",
                node.fptr_index
            );
            // file does not have clusters (i.e. is empty), allocate the first one for it
            previous = self.allocate_cluster(0)?;
            let node = get_node_mut!(self, &nid);
            node.fptr_cluster = previous;
            node.start_cluster = node.fptr_cluster;
            allocated = 1;
            // file consists of only one cluster, so it's contiguous
            node.is_contiguous = true;
        } else {
            // get the last cluster of the file
            previous = self.advance_cluster(nid, current - 1)?;
        }

        while allocated < difference {
            let next = match self.allocate_cluster(previous + 1) {
                Ok(v) => v,
                Err(e) => {
                    return Err(e.into());
                }
            };
            let node = get_node!(self, &nid);
            if next != previous + 1 && node.is_contiguous {
                // it's a pity, but we are not able to keep the file contiguous anymore
                self.make_noncontiguous(node.start_cluster, previous)?;
                let node = get_node_mut!(self, &nid);
                node.is_contiguous = false;
                node.is_dirty = true;
            }
            self.set_next_cluster(get_node!(self, &nid).is_contiguous, previous, next)?;
            previous = next;
            allocated += 1;
        }

        Ok(self.set_next_cluster(
            get_node!(self, &nid).is_contiguous,
            previous,
            crate::fs::EXFAT_CLUSTER_END,
        )?)
    }

    fn shrink_file(
        &mut self,
        nid: crate::node::Nid,
        current: u32,
        difference: u32,
    ) -> crate::Result<()> {
        assert_ne!(difference, 0, "zero difference passed");
        assert_ne!(
            get_node!(self, &nid).start_cluster,
            crate::fs::EXFAT_CLUSTER_FREE,
            "unable to shrink empty file ({current} clusters)"
        );
        assert!(
            current >= difference,
            "file underflow ({current} < {difference})"
        );

        // crop the file
        let mut previous;
        if current > difference {
            let last = self.advance_cluster(nid, current - difference - 1)?;
            previous = self.next_cluster(nid, last);
            self.set_next_cluster(
                get_node!(self, &nid).is_contiguous,
                last,
                crate::fs::EXFAT_CLUSTER_END,
            )?;
        } else {
            let node = get_node_mut!(self, &nid);
            previous = node.start_cluster;
            node.start_cluster = crate::fs::EXFAT_CLUSTER_FREE;
            node.is_dirty = true;
        }
        let node = get_node_mut!(self, &nid);
        node.fptr_index = 0;
        node.fptr_cluster = node.start_cluster;

        // free remaining clusters
        let mut difference = difference;
        while difference > 0 {
            if self.cluster_invalid(previous) {
                println!("invalid cluster {previous:#x} while freeing after shrink");
                return Err(crate::Error::Errno(EIO.into()));
            }
            let next = self.next_cluster(nid, previous);
            self.set_next_cluster(
                get_node!(self, &nid).is_contiguous,
                previous,
                crate::fs::EXFAT_CLUSTER_FREE,
            )?;
            self.free_cluster(previous)?;
            previous = next;
            difference -= 1;
        }
        Ok(())
    }

    fn erase_raw(&mut self, size: u64, offset: u64) -> std::io::Result<()> {
        if let Err(e) = self
            .dev
            .pwrite(&self.zero_cluster[..size.try_into().unwrap()], offset)
        {
            println!("failed to erase {size} bytes at {offset}");
            return Err(e);
        }
        Ok(())
    }

    fn erase_range(&mut self, nid: crate::node::Nid, begin: u64, end: u64) -> crate::Result<()> {
        if begin >= end {
            return Ok(());
        }
        let cluster_size = self.get_cluster_size();
        let count = match (begin / cluster_size).try_into() {
            Ok(v) => v,
            Err(e) => {
                println!("{e}");
                return Err(crate::Error::Errno(EINVAL.into()));
            }
        };
        let mut cluster = self.advance_cluster(nid, count)?;

        // erase from the beginning to the closest cluster boundary
        let mut cluster_boundary = (begin | (cluster_size - 1)) + 1;
        self.erase_raw(
            core::cmp::min(cluster_boundary, end) - begin,
            self.c2o(cluster) + begin % cluster_size,
        )?;

        // erase whole clusters
        while cluster_boundary < end {
            cluster = self.next_cluster(nid, cluster);
            // the cluster cannot be invalid because we have just allocated it
            assert!(
                !self.cluster_invalid(cluster),
                "invalid cluster {cluster:#x} after allocation"
            );
            self.erase_raw(cluster_size, self.c2o(cluster))?;
            cluster_boundary += cluster_size;
        }
        Ok(())
    }

    /// # Errors
    /// # Panics
    pub fn truncate(&mut self, nid: crate::node::Nid, size: u64, erase: bool) -> crate::Result<()> {
        let node = get_node!(self, &nid);
        assert!(
            node.references != 0 || node.pnid == crate::node::NID_NONE,
            "no references, node changes can be lost, pnid {}",
            node.pnid
        );
        if node.size == size {
            return Ok(());
        }

        let c1 = self.bytes2clusters(node.size)?;
        let c2 = self.bytes2clusters(size)?;
        match c1.cmp(&c2) {
            core::cmp::Ordering::Less => self.grow_file(nid, c1, c2 - c1)?,
            core::cmp::Ordering::Greater => self.shrink_file(nid, c1, c1 - c2)?,
            core::cmp::Ordering::Equal => (),
        }

        get_node_mut!(self, &nid).valid_size = if erase {
            self.erase_range(nid, get_node!(self, &nid).valid_size, size)?;
            size
        } else {
            core::cmp::min(get_node!(self, &nid).valid_size, size)
        };

        let node = get_node_mut!(self, &nid);
        node.update_mtime();
        node.size = size;
        node.is_dirty = true;
        Ok(())
    }

    /// # Errors
    /// # Panics
    pub fn get_free_clusters(&self) -> crate::Result<u32> {
        let mut free_clusters = 0;
        for i in 0..self.cmap.count.try_into().unwrap() {
            if !self.cmap.chunk.is_set(i)? {
                free_clusters += 1;
            }
        }
        Ok(free_clusters)
    }

    fn find_used_clusters(&self, a: &mut u32, b: &mut u32) -> crate::Result<bool> {
        let end = u32::from_le(self.sb.cluster_count);
        let mut va;
        let mut vb = *b;

        // find first used cluster
        va = vb + 1;
        while va < end {
            let i = match (va - crate::fs::EXFAT_FIRST_DATA_CLUSTER).try_into() {
                Ok(v) => v,
                Err(e) => {
                    println!("{e}");
                    return Err(crate::Error::Errno(EINVAL));
                }
            };
            if self.cmap.chunk.is_set(i)? {
                break;
            }
            va += 1;
        }
        *a = va;
        if va >= end {
            return Ok(false);
        }

        // find last contiguous used cluster
        vb = va;
        while vb < end {
            let i = match (vb - crate::fs::EXFAT_FIRST_DATA_CLUSTER).try_into() {
                Ok(v) => v,
                Err(e) => {
                    println!("{e}");
                    return Err(crate::Error::Errno(EINVAL));
                }
            };
            if !self.cmap.chunk.is_set(i)? {
                vb -= 1;
                break;
            }
            vb += 1;
        }
        *b = vb;
        Ok(true)
    }

    /// # Errors
    pub fn find_used_sectors(&self, a: &mut u64, b: &mut u64) -> crate::Result<bool> {
        let (mut ca, mut cb) = if *a == 0 && *b == 0 {
            (
                crate::fs::EXFAT_FIRST_DATA_CLUSTER - 1,
                crate::fs::EXFAT_FIRST_DATA_CLUSTER - 1,
            )
        } else {
            (self.s2c(*a)?, self.s2c(*b)?)
        };
        if !self.find_used_clusters(&mut ca, &mut cb)? {
            return Ok(false);
        }
        if *a != 0 || *b != 0 {
            *a = self.c2s(ca);
        }
        *b = self.c2s(cb) + (self.get_cluster_size() - 1) / self.get_sector_size();
        Ok(true)
    }

    /// # Errors
    /// # Panics
    pub fn pread(
        &mut self,
        nid: crate::node::Nid,
        buf: &mut [u8],
        offset: u64,
    ) -> crate::Result<u64> {
        let size = buf.len().try_into().unwrap();
        let node = get_node!(self, &nid);
        let node_valid_size = node.valid_size; // won't change
        let node_size = node.size; // won't change

        let offset_orig = offset;
        if offset >= node_size || size == 0 {
            return Ok(0);
        }
        if offset + size > node_valid_size {
            let mut bytes = 0;
            if offset < node_valid_size {
                bytes = self.pread(
                    nid,
                    &mut buf[..(node_valid_size - offset).try_into().unwrap()],
                    offset_orig,
                )?;
                if bytes < node_valid_size - offset {
                    return Ok(bytes);
                }
            }
            for i in 0..core::cmp::min(size - bytes, node_size - node_valid_size) {
                buf[usize::try_from(bytes + i).unwrap()] = 0;
            }
            return Ok(core::cmp::min(size, node_size - offset));
        }

        let cluster_size = self.get_cluster_size();
        let mut cluster = self.advance_cluster(nid, (offset / cluster_size).try_into().unwrap())?;
        let mut loffset = offset % cluster_size;
        let mut remainder = core::cmp::min(size, node_size - offset);
        let mut i = 0;

        while remainder > 0 {
            if self.cluster_invalid(cluster) {
                println!("invalid cluster {cluster:#x} while reading");
                return Err(crate::Error::Errno(EIO.into()));
            }
            let lsize = core::cmp::min(cluster_size - loffset, remainder);
            let lsize_usize = usize::try_from(lsize).unwrap();
            let buf = &mut buf[i..(i + lsize_usize)];
            if let Err(e) = self.dev.pread(buf, self.c2o(cluster) + loffset) {
                println!("failed to read cluster {cluster:#x}");
                return Err(e.into());
            }
            i += lsize_usize;
            loffset = 0;
            remainder -= lsize;
            cluster = self.next_cluster(nid, cluster);
        }

        let node = get_node_mut!(self, &nid);
        if !node.is_directory() && self.ro == 0 && !self.opt.noatime {
            node.update_atime();
        }
        Ok(core::cmp::min(size, node_size - offset) - remainder)
    }

    /// # Errors
    /// # Panics
    pub fn pread_async(
        &mut self,
        nid: crate::node::Nid,
        offset: u64,
        async_read: &mut AsyncRead,
    ) -> crate::Result<u64> {
        let size = async_read.buf_size.try_into().unwrap();
        let node = get_node!(self, &nid);
        let node_valid_size = node.valid_size; // won't change
        let node_size = node.size; // won't change

        let offset_orig = offset;
        if offset >= node_size || size == 0 {
            return Ok(0);
        }
        if offset + size > node_valid_size {
            let mut bytes = 0;
            if offset < node_valid_size {
                async_read.buf_size = (node_valid_size - offset).try_into().unwrap();
                bytes = self.pread_async(
                    nid,
                    offset_orig,
                    async_read
                )?;
                if bytes < node_valid_size - offset {
                    return Ok(bytes);
                }
            }
            async_read.fill_zero(bytes.try_into().unwrap());
            return Ok(core::cmp::min(size, node_size - offset));
        }

        let cluster_size = self.get_cluster_size();
        let mut cluster = self.advance_cluster(nid, (offset / cluster_size).try_into().unwrap())?;
        let mut loffset = offset % cluster_size;
        let mut remainder = core::cmp::min(size, node_size - offset);

        while remainder > 0 {
            if self.cluster_invalid(cluster) {
                println!("invalid cluster {cluster:#x} while reading");
                return Err(crate::Error::Errno(EIO.into()));
            }
            let lsize = core::cmp::min(cluster_size - loffset, remainder);
            let lsize_usize = usize::try_from(lsize).unwrap();
            if let Err(e) = self.dev.pread_async(lsize_usize, self.c2o(cluster) + loffset, async_read) {
                println!("failed to read cluster {cluster:#x}");
                return Err(e.into());
            }
            loffset = 0;
            remainder -= lsize;
            cluster = self.next_cluster(nid, cluster);
        }

        let node = get_node_mut!(self, &nid);
        if !node.is_directory() && self.ro == 0 && !self.opt.noatime {
            node.update_atime();
        }
        Ok(core::cmp::min(size, node_size - offset) - remainder)
    }

    /// # Errors
    /// # Panics
    pub fn pwrite(&mut self, nid: crate::node::Nid, buf: &[u8], offset: u64) -> crate::Result<u64> {
        let size = buf.len().try_into().unwrap();
        if offset > get_node!(self, &nid).size {
            self.truncate(nid, offset, true)?;
        }
        if offset + size > get_node!(self, &nid).size {
            self.truncate(nid, offset + size, false)?;
        }
        if size == 0 {
            return Ok(0);
        }

        let cluster_size = self.get_cluster_size();
        let mut cluster = self.advance_cluster(nid, (offset / cluster_size).try_into().unwrap())?;
        let mut loffset = offset % cluster_size;
        let mut remainder = size;
        let mut i = 0;

        while remainder > 0 {
            if self.cluster_invalid(cluster) {
                println!("invalid cluster {cluster:#x} while writing");
                return Err(crate::Error::Errno(EIO.into()));
            }
            let lsize = core::cmp::min(cluster_size - loffset, remainder);
            let lsize_usize = usize::try_from(lsize).unwrap();
            let buf = &buf[i..(i + lsize_usize)];
            if let Err(e) = self.dev.pwrite(buf, self.c2o(cluster) + loffset) {
                println!("failed to write cluster {cluster:#x}");
                return Err(e.into());
            }
            i += lsize_usize;
            loffset = 0;
            remainder -= lsize;
            let node = get_node_mut!(self, &nid);
            node.valid_size = core::cmp::max(node.valid_size, offset + size - remainder);
            cluster = self.next_cluster(nid, cluster);
        }

        let node = get_node_mut!(self, &nid);
        if !node.is_directory() {
            // directory's mtime should be updated by the caller only when it
            // creates or removes something in this directory
            node.update_mtime();
        }
        Ok(size - remainder)
    }

    /// # Errors
    /// # Panics
    pub fn pwrite_async(
        &mut self,
        nid: crate::node::Nid,
        offset: u64,
        async_write: &mut AsyncWrite
    ) -> crate::Result<u64> {
        let size = async_write.buf_size.try_into().unwrap();
        if offset > get_node!(self, &nid).size {
            self.truncate(nid, offset, true)?;
        }
        if offset + size > get_node!(self, &nid).size {
            self.truncate(nid, offset + size, false)?;
        }
        if size == 0 {
            return Ok(0);
        }

        let cluster_size = self.get_cluster_size();
        let mut cluster = self.advance_cluster(nid, (offset / cluster_size).try_into().unwrap())?;
        let mut loffset = offset % cluster_size;
        let mut remainder = size;

        while remainder > 0 {
            if self.cluster_invalid(cluster) {
                println!("invalid cluster {cluster:#x} while writing");
                return Err(crate::Error::Errno(EIO.into()));
            }
            let lsize = core::cmp::min(cluster_size - loffset, remainder);
            let lsize_usize = usize::try_from(lsize).unwrap();
            if let Err(e) = self.dev.pwrite_async(lsize_usize, self.c2o(cluster) + loffset, async_write) {
                println!("failed to write cluster {cluster:#x}");
                return Err(e.into());
            }
            loffset = 0;
            remainder -= lsize;
            let node = get_node_mut!(self, &nid);
            node.valid_size = core::cmp::max(node.valid_size, offset + size - remainder);
            cluster = self.next_cluster(nid, cluster);
        }

        let node = get_node_mut!(self, &nid);
        if !node.is_directory() {
            // directory's mtime should be updated by the caller only when it
            // creates or removes something in this directory
            node.update_mtime();
        }
        Ok(size - remainder)
    }

    fn read_entries(
        &mut self,
        dnid: crate::node::Nid,
        n: usize,
        offset: u64,
    ) -> crate::Result<Vec<crate::fs::ExfatEntry>> {
        assert_ne!(n, 0);
        assert!(
            get_node!(self, &dnid).is_directory(),
            "attempted to read entries from a file"
        );
        let mut entries = crate::fs::ExfatEntry::bulk_new(n);
        let buf_size = crate::fs::EXFAT_ENTRY_SIZE * n;
        let mut buf = vec![0; buf_size];
        let size = self.pread(dnid, &mut buf, offset)?;
        if size == buf_size.try_into().unwrap() {
            for (i, entry) in entries.iter_mut().enumerate() {
                let beg = crate::fs::EXFAT_ENTRY_SIZE * i;
                let end = beg + crate::fs::EXFAT_ENTRY_SIZE;
                *entry = *libfs::cast::align_to::<crate::fs::ExfatEntry>(&buf[beg..end]);
                // extra copy
            }
            return Ok(entries); // success
        }
        if size == 0 {
            return Err(crate::Error::Errno(ENOENT.into()));
        }
        println!("read {size} bytes instead of {buf_size} bytes");
        Err(crate::Error::Errno(EIO.into()))
    }

    fn write_entries(
        &mut self,
        dnid: crate::node::Nid,
        entries: &[crate::fs::ExfatEntry],
        n: usize,
        offset: u64,
    ) -> crate::Result<()> {
        assert_ne!(n, 0);
        assert!(
            get_node!(self, &dnid).is_directory(),
            "attempted to write entries into a file"
        );
        let mut buf = vec![];
        for entry in entries.iter().take(n) {
            buf.extend_from_slice(libfs::cast::as_u8_slice(entry)); // extra copy
        }
        let buf_size = crate::fs::EXFAT_ENTRY_SIZE * n;
        assert_eq!(buf.len(), buf_size);
        let size = self.pwrite(dnid, &buf, offset)?;
        if size == buf_size.try_into().unwrap() {
            return Ok(()); // success
        }
        println!("wrote {size} bytes instead of {buf_size} bytes");
        Err(crate::Error::Errno(EIO.into()))
    }

    fn check_entries(entry: &[crate::fs::ExfatEntry], n: usize) -> bool {
        const ENTRY_FILE_I32: i32 = crate::fs::EXFAT_ENTRY_FILE as i32;
        const ENTRY_FILE_INFO_I32: i32 = crate::fs::EXFAT_ENTRY_FILE_INFO as i32;
        const ENTRY_FILE_NAME_I32: i32 = crate::fs::EXFAT_ENTRY_FILE_NAME as i32;
        const ENTRY_FILE_TAIL_I32: i32 = crate::fs::EXFAT_ENTRY_FILE_TAIL as i32;

        const ENTRY_MAX: u8 = 0xff;
        const ENTRY_MAX_I32: i32 = ENTRY_MAX as i32;
        const ENTRY_VOID: i32 = -1;

        let mut previous = ENTRY_VOID;
        let mut current;
        // check transitions between entries types
        for (i, x) in entry.iter().enumerate().take(n + 1) {
            current = if i < n { x.typ } else { ENTRY_MAX };
            let valid = match previous {
                ENTRY_VOID => current == crate::fs::EXFAT_ENTRY_FILE,
                ENTRY_FILE_I32 => current == crate::fs::EXFAT_ENTRY_FILE_INFO,
                ENTRY_FILE_INFO_I32 => current == crate::fs::EXFAT_ENTRY_FILE_NAME,
                ENTRY_FILE_NAME_I32 => {
                    if current == crate::fs::EXFAT_ENTRY_FILE_NAME || current == ENTRY_MAX {
                        true
                    } else {
                        current >= crate::fs::EXFAT_ENTRY_FILE_TAIL
                    }
                }
                ENTRY_FILE_TAIL_I32..=ENTRY_MAX_I32 => {
                    if current == ENTRY_MAX {
                        true
                    } else {
                        current >= crate::fs::EXFAT_ENTRY_FILE_TAIL
                    }
                }
                _ => false,
            };
            if !valid {
                for x in entry {
                    println!("{x:?}");
                }
                println!("unexpected entry type {current:#x} after {previous:#x} at {i}/{n}");
            }
            previous = current.into();
        }
        true
    }

    fn check_node(
        &mut self,
        nid: crate::node::Nid,
        actual_checksum: u16,
        meta1: &crate::fs::ExfatEntryMeta1,
    ) -> bool {
        let mut ret = true;
        // Validate checksum first. If it's invalid all other fields probably
        // contain just garbage.
        if u16::from_le(actual_checksum) != u16::from_le(meta1.checksum) {
            println!(
                "'{}' has invalid checksum ({:#x} != {:#x})",
                get_node!(self, &nid).get_name(),
                u16::from_le(actual_checksum),
                u16::from_le(meta1.checksum)
            );
            if !(self.ask_to_fix() && self.fix_invalid_node_checksum(nid)) {
                ret = false;
            }
        }

        // exFAT does not support sparse files but allows files with uninitialized
        // clusters. For such files valid_size means initialized data size and
        // cannot be greater than file size. See SetFileValidData() function
        // description in MSDN.
        let node = get_node!(self, &nid);
        if node.valid_size > node.size {
            println!(
                "'{}' has valid size ({}) greater than size ({})",
                node.get_name(),
                node.valid_size,
                node.size
            );
            ret = false;
        }

        // Empty file must have zero start cluster. Non-empty file must start
        // with a valid cluster. Directories cannot be empty (i.e. must always
        // have a valid start cluster), but we will check this later while
        // reading that directory to give user a chance to read this directory.
        let node = get_node!(self, &nid);
        if node.size == 0 && node.start_cluster != crate::fs::EXFAT_CLUSTER_FREE {
            println!(
                "'{}' is empty but start cluster is {:#x}",
                node.get_name(),
                node.start_cluster
            );
            ret = false;
        }
        let node = get_node!(self, &nid);
        if node.size > 0 && self.cluster_invalid(node.start_cluster) {
            println!(
                "'{}' points to invalid cluster {:#x}",
                node.get_name(),
                node.start_cluster
            );
            ret = false;
        }

        // File or directory cannot be larger than clusters heap.
        let node = get_node!(self, &nid);
        let clusters_heap_size =
            u64::from(u32::from_le(self.sb.cluster_count)) * self.get_cluster_size();
        if node.size > clusters_heap_size {
            println!(
                "'{}' is larger than clusters heap: {} > {}",
                node.get_name(),
                node.size,
                clusters_heap_size
            );
            ret = false;
        }

        // Empty file or directory must be marked as non-contiguous.
        let node = get_node!(self, &nid);
        if node.size == 0 && node.is_contiguous {
            println!(
                "'{}' is empty but marked as contiguous ({:#x})",
                node.get_name(),
                node.attrib
            );
            ret = false;
        }

        // Directory size must be aligned on at cluster boundary.
        let node = get_node!(self, &nid);
        if node.is_directory() && (node.size % self.get_cluster_size()) != 0 {
            println!(
                "'{}' directory size {} is not divisible by {}",
                node.get_name(),
                node.size,
                self.get_cluster_size()
            );
            ret = false;
        }
        ret
    }

    fn parse_file_entries(
        &mut self,
        dnid: crate::node::Nid,
        entries: &[crate::fs::ExfatEntry],
        n: usize,
        offset: u64,
        xname: Option<&str>,
    ) -> crate::Result<crate::node::Nid> {
        if !Self::check_entries(entries, n) {
            return Err(crate::Error::Errno(EIO));
        }

        let meta1: &crate::fs::ExfatEntryMeta1 = bytemuck::cast_ref(&entries[0]);
        if meta1.continuations < 2 {
            println!("too few continuations ({})", meta1.continuations);
            return Err(crate::Error::Errno(EIO));
        }

        let meta2: &crate::fs::ExfatEntryMeta2 = bytemuck::cast_ref(&entries[1]);
        if (meta2.flags & !(crate::fs::EXFAT_FLAG_ALWAYS1 | crate::fs::EXFAT_FLAG_CONTIGUOUS)) != 0
        {
            println!("unknown flags in meta2 ({:#x})", meta2.flags);
            return Err(crate::Error::Errno(EIO));
        }

        let mandatory_entries = 2 + crate::util::div_round_up!(
            meta2.name_length,
            u8::try_from(crate::fs::EXFAT_ENAME_MAX).unwrap()
        );
        if meta1.continuations < mandatory_entries - 1 {
            println!(
                "too few continuations ({} < {})",
                meta1.continuations,
                mandatory_entries - 1
            );
            return Err(crate::Error::Errno(EIO));
        }

        let mut node = Self::alloc_node();
        node.entry_offset = offset;
        node.init_meta1(meta1);
        node.init_meta2(meta2);
        node.init_name(&entries[2..], usize::from(mandatory_entries) - 2);
        if let Some(xname) = xname {
            if node.get_name() == xname {
                for cnid in &get_node!(self, &dnid).cnids {
                    if get_node!(self, cnid).get_name() == xname {
                        return Ok(*cnid);
                    }
                }
                println!("failed to find cnid for {xname}");
                return Err(crate::Error::Errno(ENOENT));
            }
        }
        let nid = self.nmap_attach(dnid, node)?;
        assert!(get_node!(self, &nid).is_valid());

        if !self.check_node(nid, crate::util::calc_checksum(entries, n), meta1) {
            return Err(crate::Error::Errno(EIO));
        }
        Ok(nid)
    }

    fn parse_file_entry(
        &mut self,
        dnid: crate::node::Nid,
        offset: u64,
        n: usize,
        xname: Option<&str>,
    ) -> crate::Result<(crate::node::Nid, u64)> {
        let entries = self.read_entries(dnid, n, offset)?;
        Ok((
            self.parse_file_entries(dnid, &entries, n, offset, xname)?,
            offset + crate::fs::EXFAT_ENTRY_SIZE_U64 * u64::try_from(n).unwrap(),
        ))
    }

    fn decompress_upcase(output: &mut [u16], source: &[u16], size: usize) {
        for (oi, x) in output
            .iter_mut()
            .enumerate()
            .take(crate::fs::EXFAT_UPCASE_CHARS)
        {
            *x = oi.try_into().unwrap();
        }
        let mut si = 0;
        let mut oi = 0;
        while si < size && oi < crate::fs::EXFAT_UPCASE_CHARS {
            let ch = u16::from_le(source[si]);
            if ch == 0xffff && si + 1 < size {
                // indicates a run
                si += 1;
                oi += usize::from(u16::from_le(source[si]));
            } else {
                output[oi] = ch;
                oi += 1;
            }
            si += 1;
        }
    }

    // Read one entry in a directory at offset position and build a new node
    // structure.
    fn cachedir(
        &mut self,
        dnid: crate::node::Nid,
        offset: u64,
        xname: Option<&str>,
    ) -> crate::Result<(crate::node::Nid, u64)> {
        let mut offset = offset;
        loop {
            let entry = &self.read_entries(dnid, 1, offset)?[0];
            match entry.typ {
                crate::fs::EXFAT_ENTRY_FILE => {
                    let meta1: &crate::fs::ExfatEntryMeta1 = bytemuck::cast_ref(entry);
                    return self.parse_file_entry(
                        dnid,
                        offset,
                        usize::from(1 + meta1.continuations),
                        xname,
                    );
                }
                crate::fs::EXFAT_ENTRY_UPCASE => 'upcase_label: {
                    if !self.upcase.is_empty() {
                        break 'upcase_label;
                    }
                    let upcase: &crate::fs::ExfatEntryUpcase = bytemuck::cast_ref(entry);
                    self.cachedir_entry_upcase(upcase)?;
                }
                crate::fs::EXFAT_ENTRY_BITMAP => {
                    let bitmap: &crate::fs::ExfatEntryBitmap = bytemuck::cast_ref(entry);
                    self.cachedir_entry_bitmap(bitmap)?;
                }
                crate::fs::EXFAT_ENTRY_LABEL => {
                    let label: &crate::fs::ExfatEntryLabel = bytemuck::cast_ref(entry);
                    self.cachedir_entry_label(label)?;
                }
                _ => 'default_label: {
                    if (entry.typ & crate::fs::EXFAT_ENTRY_VALID) == 0 {
                        break 'default_label; // deleted entry, ignore it
                    }
                    println!("unknown entry type {:#x}", entry.typ);
                    if !self.ask_to_fix() {
                        return Err(crate::Error::Errno(ECANCELED.into()));
                    }
                    self.fix_unknown_entry(dnid, entry, offset)?;
                }
            }
            offset += crate::fs::EXFAT_ENTRY_SIZE_U64;
        }
        // we never reach here
    }

    fn cachedir_entry_upcase(&mut self, upcase: &crate::fs::ExfatEntryUpcase) -> crate::Result<()> {
        if self.cluster_invalid(u32::from_le(upcase.start_cluster)) {
            println!(
                "invalid cluster {:#x} in upcase table",
                u32::from_le(upcase.start_cluster)
            );
            return Err(crate::Error::Errno(EIO.into()));
        }
        let upcase_size = u64::from_le(upcase.size);
        let upcase_size_usize = usize::try_from(upcase_size).unwrap();
        if upcase_size == 0
            || upcase_size_usize > crate::fs::EXFAT_UPCASE_CHARS * core::mem::size_of::<u16>()
            || upcase_size_usize % core::mem::size_of::<u16>() != 0
        {
            println!("bad upcase table size ({upcase_size} bytes)");
            return Err(crate::Error::Errno(EIO.into()));
        }

        // read compressed upcase table
        let buf = match self
            .dev
            .preadx(upcase_size, self.c2o(u32::from_le(upcase.start_cluster)))
        {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "failed to read upper case table ({} bytes starting at cluster {:#x})",
                    upcase_size,
                    u32::from_le(upcase.start_cluster)
                );
                return Err(e.into());
            }
        };

        // decompress upcase table
        let mut upcase_comp = vec![0; upcase_size_usize / core::mem::size_of::<u16>()];
        // relan/exfat implicitly assumes le
        byteorder::LittleEndian::read_u16_into(&buf, &mut upcase_comp);
        self.upcase = vec![0; crate::fs::EXFAT_UPCASE_CHARS];
        Self::decompress_upcase(
            &mut self.upcase,
            &upcase_comp,
            upcase_size_usize / core::mem::size_of::<u16>(),
        );
        Ok(())
    }

    fn cachedir_entry_bitmap(&mut self, bitmap: &crate::fs::ExfatEntryBitmap) -> crate::Result<()> {
        self.cmap.start_cluster = u32::from_le(bitmap.start_cluster);
        if self.cluster_invalid(self.cmap.start_cluster) {
            println!(
                "invalid cluster {:#x} in clusters bitmap",
                self.cmap.start_cluster
            );
            return Err(crate::Error::Errno(EIO.into()));
        }

        // bitmap can be rather big, up to 512 MB
        self.cmap.count = u32::from_le(self.sb.cluster_count);
        if u64::from_le(bitmap.size) < crate::util::div_round_up!(u64::from(self.cmap.count), 8) {
            println!(
                "invalid clusters bitmap size: {} (expected at least {})",
                u64::from_le(bitmap.size),
                crate::util::div_round_up!(self.cmap.count, 8)
            );
            return Err(crate::Error::Errno(EIO.into()));
        }

        let buf_size = crate::util::round_up!(
            u64::from(self.cmap.count),
            u64::try_from(libfs::bitmap::BLOCK_BITS).unwrap()
        ) / 8;
        let buf = match self.dev.preadx(buf_size, self.c2o(self.cmap.start_cluster)) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "failed to read clusters bitmap ({} bytes starting at cluster {:#x})",
                    u64::from_le(bitmap.size),
                    self.cmap.start_cluster
                );
                return Err(e.into());
            }
        };
        Ok(self.cmap.chunk.set_bytes(&buf)?)
    }

    fn cachedir_entry_label(&mut self, label: &crate::fs::ExfatEntryLabel) -> crate::Result<()> {
        if usize::from(label.length) > crate::fs::EXFAT_ENAME_MAX {
            println!("too long label ({} chars)", label.length);
            return Err(crate::Error::Errno(EIO));
        }
        let output = crate::utf::utf16_to_utf8(
            &label.name,
            UTF8_ENAME_BUFFER_MAX,
            crate::fs::EXFAT_ENAME_MAX,
        )?;
        self.init_label(&output);
        Ok(())
    }

    fn cache_directory(&mut self, dnid: crate::node::Nid) -> crate::Result<()> {
        if get_node!(self, &dnid).is_cached {
            return Ok(()); // already cached
        }
        self.cache_directory_impl(dnid, None)
    }

    pub(crate) fn recache_directory(
        &mut self,
        dnid: crate::node::Nid,
        xname: &str,
    ) -> crate::Result<()> {
        self.cache_directory_impl(dnid, Some(xname))
    }

    fn cache_directory_impl(
        &mut self,
        dnid: crate::node::Nid,
        xname: Option<&str>,
    ) -> crate::Result<()> {
        let mut nids = vec![];
        let mut offset = 0;
        loop {
            let (nid, next) = match self.cachedir(dnid, offset, xname) {
                Ok(v) => v,
                Err(e) => {
                    if let crate::Error::Errno(e) = e {
                        if e == ENOENT {
                            break;
                        }
                    }
                    // relan/exfat rollbacks all nodes in this directory
                    // (not just the ones added now)
                    for nid in &nids {
                        self.nmap_detach(dnid, *nid)?;
                    }
                    return Err(e);
                }
            };
            if nid != crate::node::NID_NONE {
                nids.push(nid);
            }
            offset = next;
        }
        get_node_mut!(self, &dnid).is_cached = true;
        Ok(())
    }

    fn nmap_attach(
        &mut self,
        dnid: crate::node::Nid,
        mut node: crate::node::Node,
    ) -> crate::Result<crate::node::Nid> {
        assert_eq!(node.nid, crate::node::NID_NONE);
        node.nid = self.alloc_nid()?;
        Ok(self.nmap_attach_node(dnid, node))
    }

    fn nmap_attach_node(
        &mut self,
        dnid: crate::node::Nid,
        mut node: crate::node::Node,
    ) -> crate::node::Nid {
        assert_ne!(dnid, crate::node::NID_NONE);
        assert_ne!(node.nid, crate::node::NID_NONE);
        assert_ne!(node.nid, crate::node::NID_ROOT); // root directly uses nmap
        let dnode = get_node_mut!(self, &dnid);
        node.pnid = dnode.nid;
        dnode.cnids.push(node.nid);
        let nid = node.nid;
        assert!(self.nmap.insert(node.nid, node).is_none());
        nid
    }

    pub(crate) fn nmap_detach(
        &mut self,
        dnid: crate::node::Nid,
        nid: crate::node::Nid,
    ) -> crate::Result<crate::node::Node> {
        let node = self.nmap_detach_node(dnid, nid)?;
        self.free_nid(nid)?;
        Ok(node)
    }

    fn nmap_detach_node(
        &mut self,
        dnid: crate::node::Nid,
        nid: crate::node::Nid,
    ) -> crate::Result<crate::node::Node> {
        assert_ne!(dnid, crate::node::NID_NONE);
        assert_ne!(nid, crate::node::NID_NONE);
        assert_ne!(nid, crate::node::NID_ROOT); // root directly uses nmap
        let dnode = get_node_mut!(self, &dnid);
        if let Some(i) = dnode.cnids.iter().position(|x| *x == nid) {
            dnode.cnids.swap_remove(i);
            let Some(mut node) = self.nmap.remove(&nid) else {
                return Err(crate::Error::Errno(ENOENT));
            };
            node.pnid = crate::node::NID_NONE; // sanity
            Ok(node)
        } else {
            Err(crate::Error::Errno(ENOENT))
        }
    }

    fn reset_node(&mut self) -> crate::Result<()> {
        self.reset_node_impl(crate::node::NID_ROOT)
    }

    fn reset_node_impl(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        while !get_node!(self, &nid).cnids.is_empty() {
            let cnid = get_node!(self, &nid).cnids[0];
            self.reset_node_impl(cnid)?;
            self.nmap_detach(nid, cnid)?;
        }
        let node = get_node_mut!(self, &nid);
        node.is_cached = false;
        assert_eq!(
            node.references,
            0,
            "non-zero reference counter ({}) for '{}'",
            node.references,
            node.get_name()
        ); // exfat_warn() in relan/exfat
        assert!(
            node.nid == crate::node::NID_ROOT || !node.is_dirty,
            "node '{}' is dirty",
            node.get_name()
        );
        while node.references > 0 {
            node.put();
        }
        Ok(())
    }

    /// # Errors
    /// # Panics
    pub fn flush_node(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        let node = get_node!(self, &nid);
        if !node.is_dirty {
            return Ok(()); // no need to flush
        }
        assert_eq!(self.ro, 0, "unable to flush node to read-only FS");
        if node.pnid == crate::node::NID_NONE {
            return Ok(()); // do not flush unlinked node
        }

        let mut entries = self.read_entries(
            node.pnid,
            (1 + node.continuations).into(),
            node.entry_offset,
        )?;
        let node = get_node!(self, &nid);
        if !Self::check_entries(&entries, (1 + node.continuations).into()) {
            return Err(crate::Error::Errno(EIO.into()));
        }

        let node = get_node!(self, &nid);
        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.attrib = node.attrib.to_le();
        let (date, time, centisec, tzoffset) = crate::time::unix2exfat(node.mtime);
        meta1.mdate = date;
        meta1.mtime = time;
        meta1.mtime_cs = centisec;
        meta1.mtime_tzo = tzoffset;
        let (date, time, _, tzoffset) = crate::time::unix2exfat(node.atime);
        meta1.adate = date;
        meta1.atime = time;
        meta1.atime_tzo = tzoffset;

        let meta2: &mut crate::fs::ExfatEntryMeta2 = bytemuck::cast_mut(&mut entries[1]);
        meta2.valid_size = node.valid_size.to_le();
        meta2.size = node.size.to_le();
        meta2.start_cluster = node.start_cluster.to_le();
        meta2.flags = crate::fs::EXFAT_FLAG_ALWAYS1;
        // empty files must not be marked as contiguous
        if node.size != 0 && node.is_contiguous {
            meta2.flags |= crate::fs::EXFAT_FLAG_CONTIGUOUS;
        }
        // name hash remains unchanged, no need to recalculate it

        let checksum = crate::util::calc_checksum(&entries, (1 + node.continuations).into());
        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.checksum = checksum;
        self.write_entries(
            node.pnid,
            &entries,
            (1 + node.continuations).into(),
            node.entry_offset,
        )?;
        get_node_mut!(self, &nid).is_dirty = false;
        self.flush()
    }

    fn erase_entries(
        &mut self,
        dnid: crate::node::Nid,
        n: usize,
        offset: u64,
    ) -> crate::Result<()> {
        let mut entries = self.read_entries(dnid, n, offset)?;
        for entry in &mut entries {
            entry.typ &= !crate::fs::EXFAT_ENTRY_VALID;
        }
        self.write_entries(dnid, &entries, n, offset)
    }

    fn erase_node(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        let node = get_node!(self, &nid);
        let dnid = node.pnid;
        let node_continuations = node.continuations;
        let node_entry_offset = node.entry_offset;
        get_node_mut!(self, &dnid).get();
        if let Err(e) = self.erase_entries(dnid, (1 + node_continuations).into(), node_entry_offset)
        {
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }
        let result = self.flush_node(dnid);
        get_node_mut!(self, &dnid).put();
        result
    }

    fn shrink_directory(
        &mut self,
        dnid: crate::node::Nid,
        deleted_offset: u64,
    ) -> crate::Result<()> {
        let dnode = get_node!(self, &dnid);
        assert!(dnode.is_directory(), "attempted to shrink a file");
        assert!(dnode.is_cached, "attempted to shrink uncached directory");

        let mut last_nid = crate::node::NID_NONE;
        if !dnode.cnids.is_empty() {
            last_nid = dnode.cnids[0];
            for cnid in &dnode.cnids {
                let node = get_node!(self, cnid);
                if deleted_offset < node.entry_offset {
                    // there are other entries after the removed one, no way to shrink
                    // this directory
                    return Ok(());
                }
                if get_node!(self, &last_nid).entry_offset < node.entry_offset {
                    last_nid = node.nid;
                }
            }
        }

        let mut entries = 0;
        if last_nid != crate::node::NID_NONE {
            let last_node = get_node!(self, &last_nid);
            // offset of the last entry
            entries += last_node.entry_offset / crate::fs::EXFAT_ENTRY_SIZE_U64;
            // two subentries with meta info
            entries += 2;
            // subentries with file name
            entries += u64::try_from(crate::util::div_round_up!(
                crate::utf::utf16_length(&last_node.name),
                crate::fs::EXFAT_ENAME_MAX
            ))
            .unwrap();
        }

        let mut new_size = crate::util::div_round_up!(
            entries * crate::fs::EXFAT_ENTRY_SIZE_U64,
            self.get_cluster_size()
        ) * self.get_cluster_size();
        if new_size == 0 {
            // directory always has at least 1 cluster
            new_size = self.get_cluster_size();
        }
        if new_size == dnode.size {
            return Ok(());
        }
        self.truncate(dnid, new_size, true)
    }

    fn delete(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        // erase node entry from parent directory
        let dnid = get_node!(self, &nid).pnid;
        get_node_mut!(self, &dnid).get();
        if let Err(e) = self.erase_node(nid) {
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }

        // free all clusters and node structure itself
        if let Err(e) = self.truncate(nid, 0, true) {
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }
        // ^^^ relan/exfat keeps clusters until freeing node pointer,
        // but node is gone after detach in Rust.

        let deleted_offset = get_node!(self, &nid).entry_offset;
        // detach node before shrink_directory()
        let mut node = self.nmap_detach(dnid, nid)?;
        assert!(node.references > 0);
        // can't undirty truncated node via flush_node() after erase
        node.is_dirty = false;
        // relan/exfat requires caller to put() between delete and truncate
        node.put();
        assert_eq!(node.references, 0); // node is done

        // shrink parent directory
        if let Err(e) = self.shrink_directory(dnid, deleted_offset) {
            self.flush_node(dnid);
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }

        // flush parent directory
        get_node_mut!(self, &dnid).update_mtime();
        let result = self.flush_node(dnid);
        get_node_mut!(self, &dnid).put();
        result
    }

    /// # Errors
    pub fn unlink(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        let node = get_node!(self, &nid);
        if node.references > 1 {
            return Err(crate::Error::Errno(EBUSY.into())); // XXX open-unlink unsupported
        }
        if node.is_directory() {
            return Err(crate::Error::Errno(EISDIR.into()));
        }
        self.delete(nid)
    }

    /// # Errors
    pub fn rmdir(&mut self, nid: crate::node::Nid) -> crate::Result<()> {
        let node = get_node!(self, &nid);
        if node.references > 1 {
            return Err(crate::Error::Errno(EBUSY.into())); // XXX open-unlink unsupported
        }
        if !node.is_directory() {
            return Err(crate::Error::Errno(ENOTDIR.into()));
        }
        // check that directory is empty
        self.cache_directory(nid)?; // populate cnids
        if !get_node!(self, &nid).cnids.is_empty() {
            return Err(crate::Error::Errno(ENOTEMPTY.into()));
        }
        self.delete(nid)
    }

    fn check_slot(&mut self, dnid: crate::node::Nid, offset: u64, n: usize) -> crate::Result<()> {
        // Root directory contains entries, that don't have any nodes associated
        // with them (clusters bitmap, upper case table, label). We need to be
        // careful not to overwrite them.
        if dnid != crate::node::NID_ROOT {
            return Ok(());
        }
        let entries = self.read_entries(dnid, n, offset)?;
        for entry in &entries {
            if (entry.typ & crate::fs::EXFAT_ENTRY_VALID) != 0 {
                return Err(crate::Error::Errno(EINVAL.into()));
            }
        }
        Ok(())
    }

    fn find_slot(&mut self, dnid: crate::node::Nid, n: usize) -> crate::Result<u64> {
        let dnode = get_node!(self, &dnid);
        assert!(dnode.is_cached, "directory is not cached");

        // build a bitmap of valid entries in the directory
        // relan/exfat: why calloc(..., sizeof(bitmap_t)) ?
        let nentries = usize::try_from(dnode.size).unwrap() / crate::fs::EXFAT_ENTRY_SIZE;
        let mut dmap = libfs::bitmap::Bitmap::new(nentries)?;
        for cnid in &dnode.cnids {
            let node = get_node!(self, cnid);
            for i in 0..=node.continuations {
                dmap.set(
                    usize::try_from(node.entry_offset).unwrap() / crate::fs::EXFAT_ENTRY_SIZE
                        + usize::from(i),
                )?;
            }
        }

        // find a slot in the directory entries bitmap
        let mut offset = 0;
        let mut contiguous = 0;
        let mut i = 0;
        while i < nentries {
            if dmap.is_set(i)? {
                contiguous = 0;
            } else {
                if contiguous == 0 {
                    offset = u64::try_from(i).unwrap() * crate::fs::EXFAT_ENTRY_SIZE_U64;
                }
                contiguous += 1;
                if contiguous == n {
                    // suitable slot is found, check that it's not occupied
                    match self.check_slot(dnid, offset, n) {
                        Ok(()) => return Ok(offset), // slot is free
                        Err(e) => match e {
                            crate::Error::Errno(e) => match e {
                                EINVAL => {
                                    // slot at (i-n) is occupied, go back and check (i-n+1)
                                    i -= contiguous - 1;
                                    contiguous = 0;
                                }
                                _ => return Err(e.into()),
                            },
                            crate::Error::Error(e) => return Err(e.into()),
                        },
                    }
                }
            }
            i += 1;
        }

        // no suitable slots found, extend the directory
        let dir_size = get_node!(self, &dnid).size;
        if contiguous == 0 {
            offset = dir_size;
        }
        self.truncate(
            dnid,
            crate::util::round_up!(
                dir_size + crate::fs::EXFAT_ENTRY_SIZE_U64 * u64::try_from(n - contiguous).unwrap(),
                self.get_cluster_size()
            ),
            true,
        )?;
        Ok(offset)
    }

    fn commit_entry(
        &mut self,
        dnid: crate::node::Nid,
        name: &[u16],
        offset: u64,
        attrib: u16,
    ) -> crate::Result<crate::node::Nid> {
        let name_length = crate::utf::utf16_length(name);
        let name_entries = crate::util::div_round_up!(name_length, crate::fs::EXFAT_ENAME_MAX);
        let mut entries = crate::fs::ExfatEntry::bulk_new(2 + name_entries);

        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.typ = crate::fs::EXFAT_ENTRY_FILE;
        meta1.continuations = (1 + name_entries).try_into().unwrap();
        meta1.attrib = attrib.to_le();
        let (date, time, centisec, tzoffset) =
            crate::time::unix2exfat(libfs::time::get_current().unwrap());
        meta1.adate = date;
        meta1.mdate = date;
        meta1.crdate = date;
        meta1.atime = time;
        meta1.mtime = time;
        meta1.crtime = time;
        meta1.mtime_cs = centisec; // there is no atime_cs
        meta1.crtime_cs = centisec;
        meta1.atime_tzo = tzoffset;
        meta1.mtime_tzo = tzoffset;
        meta1.crtime_tzo = tzoffset;

        let meta2: &mut crate::fs::ExfatEntryMeta2 = bytemuck::cast_mut(&mut entries[1]);
        meta2.typ = crate::fs::EXFAT_ENTRY_FILE_INFO;
        meta2.flags = crate::fs::EXFAT_FLAG_ALWAYS1;
        meta2.name_length = name_length.try_into().unwrap();
        meta2.name_hash = crate::util::calc_name_hash(&self.upcase, name, name_length);
        meta2.start_cluster = crate::fs::EXFAT_CLUSTER_FREE.to_le();

        for i in 0..name_entries {
            let name_entry: &mut crate::fs::ExfatEntryName =
                bytemuck::cast_mut(&mut entries[2 + i]);
            name_entry.typ = crate::fs::EXFAT_ENTRY_FILE_NAME;
            name_entry.unknown = 0;
            let name = &name[(i * crate::fs::EXFAT_ENAME_MAX)..];
            name_entry
                .name
                .copy_from_slice(&name[..crate::fs::EXFAT_ENAME_MAX]);
        }

        let checksum = crate::util::calc_checksum(&entries, 2 + name_entries);
        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.checksum = checksum;
        self.write_entries(dnid, &entries, 2 + name_entries, offset)?;

        let mut node = Self::alloc_node();
        node.entry_offset = offset;
        node.init_meta1(bytemuck::cast_ref(&entries[0]));
        node.init_meta2(bytemuck::cast_ref(&entries[1]));
        node.init_name(&entries[2..], name_entries);
        let nid = self.nmap_attach(dnid, node)?;
        assert!(get_node!(self, &nid).is_valid());
        Ok(nid)
    }

    fn create(
        &mut self,
        dnid: crate::node::Nid,
        cnps: &[&str],
        attrib: u16,
    ) -> crate::Result<crate::node::Nid> {
        let (dnid, enid, name) = self.split(dnid, cnps)?;
        if enid != crate::node::NID_NONE {
            get_node_mut!(self, &enid).put();
            get_node_mut!(self, &dnid).put();
            return Err(crate::Error::Errno(EEXIST.into()));
        }
        let offset = match self.find_slot(
            dnid,
            2 + crate::util::div_round_up!(
                crate::utf::utf16_length(&name),
                crate::fs::EXFAT_ENAME_MAX
            ),
        ) {
            Ok(v) => v,
            Err(e) => {
                get_node_mut!(self, &dnid).put();
                return Err(e);
            }
        };
        let nid = match self.commit_entry(dnid, &name, offset, attrib) {
            Ok(v) => v,
            Err(e) => {
                get_node_mut!(self, &dnid).put();
                return Err(e);
            }
        };
        get_node_mut!(self, &dnid).update_mtime();
        if let Err(e) = self.flush_node(dnid) {
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }
        get_node_mut!(self, &dnid).put();
        Ok(nid)
    }

    /// # Errors
    pub fn mknod(&mut self, path: &str) -> crate::Result<crate::node::Nid> {
        self.mknod_impl(crate::node::NID_ROOT, &libfs::fs::split_path(path))
    }

    /// # Errors
    pub fn mknod_at(
        &mut self,
        dnid: crate::node::Nid,
        cnp: &str,
    ) -> crate::Result<crate::node::Nid> {
        if cnp == "." || cnp == ".." {
            return Err(crate::Error::Errno(EISDIR.into()));
        }
        self.mknod_impl(dnid, &[cnp])
    }

    fn mknod_impl(
        &mut self,
        dnid: crate::node::Nid,
        cnps: &[&str],
    ) -> crate::Result<crate::node::Nid> {
        let nid = self.create(dnid, cnps, crate::fs::EXFAT_ATTRIB_ARCH)?;
        if self.opt.debug {
            assert_eq!(nid, self.lookup_impl(dnid, cnps)?);
            get_node_mut!(self, &nid).put();
        }
        Ok(nid)
    }

    /// # Errors
    pub fn mkdir(&mut self, path: &str) -> crate::Result<crate::node::Nid> {
        self.mkdir_impl(crate::node::NID_ROOT, &libfs::fs::split_path(path))
    }

    /// # Errors
    pub fn mkdir_at(
        &mut self,
        dnid: crate::node::Nid,
        cnp: &str,
    ) -> crate::Result<crate::node::Nid> {
        if cnp == "." || cnp == ".." {
            return Err(crate::Error::Errno(EEXIST.into()));
        }
        self.mkdir_impl(dnid, &[cnp])
    }

    fn mkdir_impl(
        &mut self,
        dnid: crate::node::Nid,
        cnps: &[&str],
    ) -> crate::Result<crate::node::Nid> {
        let nid = self.create(dnid, cnps, crate::fs::EXFAT_ATTRIB_DIR)?;
        // relan/exfat unconditionally lookup the path for node
        if self.opt.debug {
            // relan/exfat returns 0 on lookup failure
            assert_eq!(nid, self.lookup_impl(dnid, cnps)?);
            get_node_mut!(self, &nid).put();
        }
        get_node_mut!(self, &nid).get();
        // directories always have at least one cluster
        if let Err(e) = self.truncate(nid, self.get_cluster_size(), true) {
            self.delete(nid);
            get_node_mut!(self, &nid).put();
            return Err(e);
        }
        if let Err(e) = self.flush_node(nid) {
            self.delete(nid);
            get_node_mut!(self, &nid).put();
            return Err(e);
        }
        get_node_mut!(self, &nid).put();
        Ok(nid)
    }

    fn rename_entry(
        &mut self,
        old_dnid: crate::node::Nid,
        new_dnid: crate::node::Nid,
        nid: crate::node::Nid,
        name: &[u16],
        new_offset: u64,
    ) -> crate::Result<crate::node::Nid> {
        let name_length = crate::utf::utf16_length(name);
        let name_entries = crate::util::div_round_up!(name_length, crate::fs::EXFAT_ENAME_MAX);

        let node = get_node!(self, &nid);
        let mut entries = self.read_entries(node.pnid, 2, node.entry_offset)?;
        let v = crate::fs::ExfatEntry::bulk_new(name_entries);
        entries.extend_from_slice(&v);
        assert_eq!(entries.len(), 2 + name_entries);

        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.continuations = (1 + name_entries).try_into().unwrap();

        let meta2: &mut crate::fs::ExfatEntryMeta2 = bytemuck::cast_mut(&mut entries[1]);
        meta2.name_length = name_length.try_into().unwrap();
        meta2.name_hash = crate::util::calc_name_hash(&self.upcase, name, name_length);

        self.erase_node(nid)?;
        let node = get_node_mut!(self, &nid);
        node.entry_offset = new_offset;
        node.continuations = (1 + name_entries).try_into().unwrap();

        for i in 0..name_entries {
            let name_entry: &mut crate::fs::ExfatEntryName =
                bytemuck::cast_mut(&mut entries[2 + i]);
            name_entry.typ = crate::fs::EXFAT_ENTRY_FILE_NAME;
            name_entry.unknown = 0;
            let name = &name[(i * crate::fs::EXFAT_ENAME_MAX)..];
            name_entry
                .name
                .copy_from_slice(&name[..crate::fs::EXFAT_ENAME_MAX]);
        }

        let checksum = crate::util::calc_checksum(&entries, 2 + name_entries);
        let meta1: &mut crate::fs::ExfatEntryMeta1 = bytemuck::cast_mut(&mut entries[0]);
        meta1.checksum = checksum;
        self.write_entries(new_dnid, &entries, 2 + name_entries, new_offset)?;

        let node = get_node_mut!(self, &nid);
        node.update_name(&entries[2..], name_entries);
        assert!(node.is_valid());

        // update pnid / cnids to move nid from old_dnid to new_dnid
        let node = self.nmap_detach_node(old_dnid, nid)?;
        assert_eq!(node.nid, nid);
        Ok(self.nmap_attach_node(new_dnid, node))
    }

    /// # Errors
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> crate::Result<crate::node::Nid> {
        self.rename_impl(
            crate::node::NID_ROOT,
            &libfs::fs::split_path(old_path),
            crate::node::NID_ROOT,
            &libfs::fs::split_path(new_path),
        )
    }

    /// # Errors
    pub fn rename_at(
        &mut self,
        old_dnid: crate::node::Nid,
        old_cnp: &str,
        new_dnid: crate::node::Nid,
        new_cnp: &str,
    ) -> crate::Result<crate::node::Nid> {
        if old_cnp == "." || old_cnp == ".." {
            return Err(crate::Error::Errno(EBUSY.into()));
        }
        self.rename_impl(old_dnid, &[old_cnp], new_dnid, &[new_cnp])
    }

    fn rename_impl(
        &mut self,
        old_dnid: crate::node::Nid,
        old_cnps: &[&str],
        new_dnid: crate::node::Nid,
        new_cnps: &[&str],
    ) -> crate::Result<crate::node::Nid> {
        let nid = self.lookup_impl(old_dnid, old_cnps)?;
        let (dnid, enid, name) = match self.split(new_dnid, new_cnps) {
            Ok(v) => v,
            Err(e) => {
                get_node_mut!(self, &nid).put();
                return Err(e);
            }
        };

        // check that target is not a subdirectory of the source
        if get_node!(self, &nid).is_directory() {
            let mut dnid = dnid;
            loop {
                if nid == dnid {
                    if enid != crate::node::NID_NONE {
                        get_node_mut!(self, &enid).put();
                    }
                    get_node_mut!(self, &dnid).put();
                    get_node_mut!(self, &nid).put();
                    return Err(crate::Error::Errno(EINVAL.into()));
                }
                dnid = get_node!(self, &dnid).pnid;
                if dnid == crate::node::NID_NONE {
                    break;
                }
            }
        }

        if enid != crate::node::NID_NONE {
            // remove target if it's not the same node as source
            if enid == nid {
                get_node_mut!(self, &enid).put();
            } else {
                // unlink_rename_target puts enid regardless of result
                if let Err(e) = self.unlink_rename_target(enid, nid) {
                    // free clusters even if something went wrong; otherwise they
                    // will be just lost
                    get_node_mut!(self, &dnid).put();
                    get_node_mut!(self, &nid).put();
                    return Err(e);
                }
            }
        }

        let offset = match self.find_slot(
            dnid,
            2 + crate::util::div_round_up!(
                crate::utf::utf16_length(&name),
                crate::fs::EXFAT_ENAME_MAX
            ),
        ) {
            Ok(v) => v,
            Err(e) => {
                get_node_mut!(self, &dnid).put();
                get_node_mut!(self, &nid).put();
                return Err(e);
            }
        };
        match self.rename_entry(old_dnid, dnid, nid, &name, offset) {
            Ok(v) => assert_eq!(v, nid),
            Err(e) => {
                get_node_mut!(self, &dnid).put();
                get_node_mut!(self, &nid).put();
                return Err(e);
            }
        }
        if let Err(e) = self.flush_node(dnid) {
            get_node_mut!(self, &dnid).put();
            get_node_mut!(self, &nid).put();
            return Err(e);
        }
        get_node_mut!(self, &dnid).put();
        get_node_mut!(self, &nid).put();
        // node itself is not marked as dirty, no need to flush it
        Ok(nid)
    }

    fn unlink_rename_target(
        &mut self,
        enid: crate::node::Nid,
        nid: crate::node::Nid,
    ) -> crate::Result<()> {
        let existing = get_node!(self, &enid);
        assert!(existing.references > 0);
        if existing.is_directory() {
            if get_node!(self, &nid).is_directory() {
                if let Err(e) = self.rmdir(enid) {
                    if let Some(node) = self.nmap.get_mut(&enid) {
                        node.put();
                    }
                    return Err(e);
                }
                Ok(())
            } else {
                get_node_mut!(self, &enid).put();
                Err(crate::Error::Errno(ENOTDIR.into()))
            }
        } else if true {
            if get_node!(self, &nid).is_directory() {
                get_node_mut!(self, &enid).put();
                Err(crate::Error::Errno(EISDIR.into()))
            } else {
                if let Err(e) = self.unlink(enid) {
                    if let Some(node) = self.nmap.get_mut(&enid) {
                        node.put();
                    }
                    return Err(e);
                }
                Ok(())
            }
        } else {
            unreachable!();
        }
    }

    fn find_label_entry(&mut self) -> crate::Result<u64> {
        let mut offset = 0;
        loop {
            let entry = &self.read_entries(crate::node::NID_ROOT, 1, offset)?[0];
            if entry.typ == crate::fs::EXFAT_ENTRY_LABEL {
                return Ok(offset);
            }
            offset += crate::fs::EXFAT_ENTRY_SIZE_U64;
        }
    }

    /// # Errors
    /// # Panics
    pub fn set_label(&mut self, label: &str) -> crate::Result<()> {
        let label = label.as_bytes();
        let label_utf16 =
            crate::utf::utf8_to_utf16(label, crate::fs::EXFAT_ENAME_MAX, label.len())?;

        let offset = match self.find_label_entry() {
            Ok(v) => v,
            Err(e) => match e {
                crate::Error::Errno(e) => match e {
                    ENOENT => self.find_slot(crate::node::NID_ROOT, 1)?,
                    _ => return Err(e.into()),
                },
                crate::Error::Error(e) => return Err(e.into()),
            },
        };

        let mut entry = crate::fs::ExfatEntryLabel::new();
        entry.typ = crate::fs::EXFAT_ENTRY_LABEL;
        entry.length = crate::utf::utf16_length(&label_utf16).try_into().unwrap();
        entry.name.copy_from_slice(&label_utf16);
        if entry.length == 0 {
            entry.typ ^= crate::fs::EXFAT_ENTRY_VALID;
        }

        let entry: &crate::fs::ExfatEntry = bytemuck::cast_ref(&entry);
        self.write_entries(crate::node::NID_ROOT, &[*entry], 1, offset)?;
        self.init_label(label);
        Ok(())
    }

    /// # Errors
    pub fn opendir_cursor(&mut self, dnid: crate::node::Nid) -> crate::Result<Cursor> {
        get_node_mut!(self, &dnid).get();
        if let Err(e) = self.cache_directory(dnid) {
            get_node_mut!(self, &dnid).put();
            return Err(e);
        }
        Ok(Cursor::new(dnid))
    }

    pub fn closedir_cursor(&mut self, c: Cursor) {
        get_node_mut!(self, &c.pnid).put();
    }

    /// # Errors
    /// # Panics
    pub fn readdir_cursor(&mut self, c: &mut Cursor) -> crate::Result<crate::node::Nid> {
        if c.curnid == crate::node::NID_NONE {
            let dnode = get_node!(self, &c.pnid);
            if dnode.cnids.is_empty() {
                c.curidx = usize::MAX;
                c.curnid = crate::node::NID_NONE;
            } else {
                c.curidx = 0;
                c.curnid = dnode.cnids[c.curidx];
            }
        } else {
            let dnode = get_node!(self, &c.pnid);
            if c.curidx + 1 >= dnode.cnids.len() {
                c.curidx = usize::MAX;
                c.curnid = crate::node::NID_NONE;
            } else {
                c.curidx += 1;
                c.curnid = dnode.cnids[c.curidx];
            }
        }
        if c.curnid == crate::node::NID_NONE {
            Err(crate::Error::Errno(ENOENT.into()))
        } else {
            let node = get_node_mut!(self, &c.curnid);
            node.get(); // caller needs to put this node
            assert_eq!(node.nid, c.curnid);
            Ok(node.nid)
        }
    }

    fn compare_name_char(&self, a: u16, b: u16) -> bool {
        self.upcase[usize::from(a)] == self.upcase[usize::from(b)]
    }

    fn compare_name(&self, a: &[u16], b: &[u16]) -> bool {
        assert!(!a.is_empty());
        assert!(!b.is_empty());
        let mut i = 0;
        while i < a.len() && i < b.len() {
            if !self.compare_name_char(u16::from_le(a[i]), u16::from_le(b[i])) {
                return false;
            }
            i += 1;
        }
        crate::utf::utf16_length(a) == crate::utf::utf16_length(b)
    }

    // caller needs to put returned nid
    fn lookup_name(
        &mut self,
        dnid: crate::node::Nid,
        name: &str,
        n: usize,
    ) -> crate::Result<crate::node::Nid> {
        let buf = crate::utf::utf8_to_utf16(name.as_bytes(), NAME_MAX, n)?;
        let mut c = self.opendir_cursor(dnid)?;
        loop {
            let nid = match self.readdir_cursor(&mut c) {
                Ok(v) => v,
                Err(e) => {
                    self.closedir_cursor(c);
                    return Err(e);
                }
            };
            if self.compare_name(&buf, &get_node!(self, &nid).name) {
                self.closedir_cursor(c);
                return Ok(nid);
            }
            get_node_mut!(self, &nid).put();
        }
    }

    /// # Errors
    pub fn lookup(&mut self, path: &str) -> crate::Result<crate::node::Nid> {
        self.lookup_impl(crate::node::NID_ROOT, &libfs::fs::split_path(path))
    }

    /// # Errors
    pub fn lookup_at(
        &mut self,
        dnid: crate::node::Nid,
        cnp: &str,
    ) -> crate::Result<crate::node::Nid> {
        if cnp == "." {
            return Ok(dnid);
        }
        self.lookup_impl(dnid, &[cnp])
    }

    // Unlike obscure path based abstraction provided by libfuse,
    // lookup ops in fuser simply takes component name with parent ino.
    fn lookup_impl(
        &mut self,
        dnid: crate::node::Nid,
        cnps: &[&str],
    ) -> crate::Result<crate::node::Nid> {
        let mut dnid = dnid;
        get_node_mut!(self, &dnid).get();
        for s in cnps {
            let nid = match self.lookup_name(dnid, s, s.len()) {
                Ok(v) => v,
                Err(e) => {
                    get_node_mut!(self, &dnid).put();
                    return Err(e);
                }
            };
            get_node_mut!(self, &dnid).put();
            dnid = nid; // nid is directory unless last
        }
        Ok(dnid) // dnid isn't necessarily directory
    }

    fn is_allowed_char(comp: &[u8], length: usize) -> bool {
        for x in comp.iter().take(length) {
            if *x >= 0x01 && *x <= 0x1F {
                return false;
            }
            let x = *x as char;
            match x {
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => return false,
                _ => (),
            }
        }
        true
    }

    fn split(
        &mut self,
        dnid: crate::node::Nid,
        cnps: &[&str],
    ) -> crate::Result<(crate::node::Nid, crate::node::Nid, Vec<u16>)> {
        let mut dnid = dnid;
        get_node_mut!(self, &dnid).get();
        for (i, s) in cnps.iter().enumerate() {
            if i == cnps.len() - 1 {
                let b = s.as_bytes();
                if !Self::is_allowed_char(b, b.len()) {
                    // contains characters that are not allowed
                    get_node_mut!(self, &dnid).put();
                    return Err(crate::Error::Errno(ENOENT.into()));
                }
                let name = match crate::utf::utf8_to_utf16(b, NAME_MAX, b.len()) {
                    Ok(v) => v,
                    Err(e) => {
                        get_node_mut!(self, &dnid).put();
                        return Err(e.into());
                    }
                };
                let nid = match self.lookup_name(dnid, s, s.len()) {
                    Ok(v) => v,
                    Err(e) => {
                        if let crate::Error::Errno(e) = e {
                            if e == ENOENT {
                                crate::node::NID_NONE
                            } else {
                                get_node_mut!(self, &dnid).put();
                                return Err(e.into());
                            }
                        } else {
                            get_node_mut!(self, &dnid).put();
                            return Err(e);
                        }
                    }
                };
                return Ok((dnid, nid, name)); // caller needs to put both dnid and nid
            }
            let nid = match self.lookup_name(dnid, s, s.len()) {
                Ok(v) => v,
                Err(e) => {
                    get_node_mut!(self, &dnid).put();
                    return Err(e);
                }
            };
            get_node_mut!(self, &dnid).put();
            dnid = nid; // nid is directory unless last
        }
        panic!("impossible");
    }

    fn ask_to_fix(&self) -> bool {
        match self.opt.repair {
            crate::option::RepairMode::No => false,
            crate::option::RepairMode::Yes => true,
        }
    }

    fn fix_invalid_vbr_checksum(&mut self, vbr_checksum: u32) -> std::io::Result<()> {
        let mut sector = vec![0; self.get_sector_size().try_into().unwrap()];
        assert_eq!(sector.len() % core::mem::size_of::<u32>(), 0);
        let x = core::mem::size_of_val(&vbr_checksum);
        let n = sector.len() / x;
        for i in 0..n {
            let offset = x * i;
            byteorder::LittleEndian::write_u32_into(
                &[vbr_checksum.to_le()],
                &mut sector[offset..offset + x],
            );
        }
        if let Err(e) = self.dev.pwrite(&sector, 11 * self.get_sector_size()) {
            println!("failed to write correct VBR checksum");
            return Err(e);
        }
        self.count_errors_fixed();
        Ok(())
    }

    fn fix_invalid_node_checksum(&mut self, nid: crate::node::Nid) -> bool {
        // checksum will be rewritten by exfat_flush_node()
        get_node_mut!(self, &nid).is_dirty = true;
        self.count_errors_fixed();
        true
    }

    fn fix_unknown_entry(
        &mut self,
        dnid: crate::node::Nid,
        entry: &crate::fs::ExfatEntry,
        offset: u64,
    ) -> crate::Result<()> {
        let mut deleted = *entry;
        deleted.typ &= !crate::fs::EXFAT_ENTRY_VALID;
        let buf: &[u8; crate::fs::EXFAT_ENTRY_SIZE] = bytemuck::cast_ref(&deleted);
        if self.pwrite(dnid, buf, offset)? != crate::fs::EXFAT_ENTRY_SIZE_U64 {
            return Err(crate::Error::Errno(EIO.into()));
        }
        self.count_errors_fixed();
        Ok(())
    }

    fn rootdir_size(&mut self) -> crate::Result<u64> {
        let clusters_max = u32::from_le(self.sb.cluster_count);
        let mut rootdir_cluster = u32::from_le(self.sb.rootdir_cluster);
        let mut clusters = 0;
        // Iterate all clusters of the root directory to calculate its size.
        // It can't be contiguous because there is no flag to indicate this.
        loop {
            if clusters == clusters_max {
                // infinite loop detected
                println!("root directory cannot occupy all {clusters} clusters");
                return Err(crate::Error::Errno(EIO));
            }
            if self.cluster_invalid(rootdir_cluster) {
                println!("bad cluster {rootdir_cluster:#x} while reading root directory");
                return Err(crate::Error::Errno(EIO));
            }
            rootdir_cluster = self.next_cluster(crate::node::NID_ROOT, rootdir_cluster);
            clusters += 1;
            if rootdir_cluster == crate::fs::EXFAT_CLUSTER_END {
                break;
            }
        }
        if clusters == 0 {
            println!("root directory has zero cluster");
            return Err(crate::Error::Errno(EIO));
        }
        Ok(u64::from(clusters) * self.get_cluster_size())
    }

    fn verify_vbr_checksum(&mut self) -> crate::Result<()> {
        let sector_size = self.get_sector_size();
        let sector = match self.dev.preadx(sector_size, 0) {
            Ok(v) => v,
            Err(e) => {
                println!("failed to read boot sector");
                return Err(e.into());
            }
        };

        let mut vbr_checksum = crate::util::vbr_start_checksum(&sector, sector_size);
        for i in 1..11 {
            let sector = match self.dev.preadx(sector_size, i * sector_size) {
                Ok(v) => v,
                Err(e) => {
                    println!("failed to read VBR sector");
                    return Err(e.into());
                }
            };
            vbr_checksum = crate::util::vbr_add_checksum(&sector, sector_size, vbr_checksum);
        }

        let sector = match self.dev.preadx(sector_size, 11 * sector_size) {
            Ok(v) => v,
            Err(e) => {
                println!("failed to read VBR checksum sector");
                return Err(e.into());
            }
        };

        let x = core::mem::size_of_val(&vbr_checksum);
        let n = sector.len() / x;
        for i in 0..n {
            let offset = x * i;
            let c = u32::from_le_bytes(sector[offset..offset + x].try_into().unwrap());
            if c != vbr_checksum {
                println!("invalid VBR checksum {c:#x} (expected {vbr_checksum:#x})");
                if !self.ask_to_fix() {
                    return Err(crate::Error::Errno(ECANCELED.into()));
                }
                self.fix_invalid_vbr_checksum(vbr_checksum)?;
            }
        }
        Ok(())
    }

    fn commit_super_block(&mut self) -> crate::Result<()> {
        if let Err(e) = self.dev.pwrite(libfs::cast::as_u8_slice(&self.sb), 0) {
            println!("failed to write super block");
            return Err(e.into()); // relan/exfat returns +1
        }
        self.fsync()
    }

    /// # Errors
    pub fn soil_super_block(&mut self) -> crate::Result<()> {
        if self.ro != 0 {
            return Ok(());
        }
        self.sb.volume_state =
            (u16::from_le(self.sb.volume_state) | crate::fs::EXFAT_STATE_MOUNTED).to_le();
        self.commit_super_block()
    }

    /// # Errors
    /// # Panics
    #[allow(clippy::too_many_lines)]
    pub fn mount(opt: crate::option::Opt, dev: crate::device::Device) -> crate::Result<Self> {
        if let Err(e) = crate::time::tzset() {
            return Err(crate::Error::Errno(ENXIO.into()));
        }
        crate::time::tzassert();

        let mut ef = Self::new(dev, opt);
        if let crate::option::OpenMode::Ro = ef.dev.get_mode() {
            ef.ro = match ef.opt.mode {
                crate::option::OpenMode::Any => -1, // any option -> ro device
                _ => 1,                             // ro option -> ro device
            };
        }
        assert!(ef.ro == 0 || ef.ro == 1 || ef.ro == -1);

        let buf = match ef.dev.preadx(crate::fs::EXFAT_SUPER_BLOCK_SIZE_U64, 0) {
            Ok(v) => v,
            Err(e) => {
                println!("failed to read boot sector");
                return Err(e.into());
            }
        };
        ef.sb = *libfs::cast::align_to::<crate::fs::ExfatSuperBlock>(&buf);
        log::debug!("{:?}", ef.sb);

        if ef.sb.oem_name != "EXFAT   ".as_bytes() {
            println!("exFAT file system is not found");
            return Err(crate::Error::Errno(EIO.into()));
        }
        // sector cannot be smaller than 512 bytes
        if ef.sb.sector_bits < 9 {
            println!("too small sector size: 2^{}", ef.sb.sector_bits);
            return Err(crate::Error::Errno(EIO.into()));
        }
        // officially exFAT supports cluster size up to 32 MB
        if ef.sb.sector_bits + ef.sb.spc_bits > 25 {
            println!(
                "too big cluster size: 2^({}+{})",
                ef.sb.sector_bits,
                ef.sb.spc_bits
            );
            return Err(crate::Error::Errno(EIO.into()));
        }

        ef.verify_vbr_checksum()?;

        assert!(ef.zero_cluster.is_empty());
        ef.zero_cluster
            .resize(ef.get_cluster_size().try_into().unwrap(), 0);

        if ef.sb.version_major != 1 || ef.sb.version_minor != 0 {
            println!(
                "unsupported exFAT version: {}.{}",
                ef.sb.version_major,
                ef.sb.version_minor
            );
            return Err(crate::Error::Errno(EIO.into()));
        }
        if ef.sb.fat_count != 1 {
            println!("unsupported FAT count: {}", ef.sb.fat_count);
            return Err(crate::Error::Errno(EIO.into()));
        }
        if u64::from_le(ef.sb.sector_count) * ef.get_sector_size() > ef.dev.get_size() {
            // this can cause I/O errors later but we don't fail mounting to let
            // user rescue data
            println!(
                "file system in sectors is larger than device: {} * {} > {}",
                u64::from_le(ef.sb.sector_count),
                ef.get_sector_size(),
                ef.dev.get_size()
            );
        }
        let clusters_heap_size =
            u64::from(u32::from_le(ef.sb.cluster_count)) * ef.get_cluster_size();
        if clusters_heap_size > ef.dev.get_size() {
            println!(
                "file system in clusters is larger than device: {} * {} > {}",
                u32::from_le(ef.sb.cluster_count),
                ef.get_cluster_size(),
                ef.dev.get_size()
            );
            return Err(crate::Error::Errno(EIO.into()));
        }
        if u16::from_le(ef.sb.volume_state) & crate::fs::EXFAT_STATE_MOUNTED != 0 {
            println!("volume was not unmounted cleanly");
        }

        // Rust
        ef.imap.max = match ef.opt.nidalloc {
            crate::option::NidAllocMode::Linear => crate::node::Nid::MAX - 1,
            crate::option::NidAllocMode::Bitmap => {
                // n is large enough that cluster allocation should fail first
                let n = crate::util::round_up!(
                    usize::try_from(clusters_heap_size).unwrap()
                        / (crate::fs::EXFAT_ENTRY_SIZE * 3),
                    libfs::bitmap::BLOCK_BITS
                );
                log::debug!("imap: {} bits, {} bytes", n, n / 8);
                ef.imap.chunk = libfs::bitmap::Bitmap::new(n)?;
                (n - 1).try_into().unwrap()
            }
        };

        let root = crate::node::Node::new_root();
        assert_eq!(root.nid, crate::node::NID_ROOT);
        assert_eq!(root.pnid, crate::node::NID_NONE);
        let nid = root.nid;
        ef.insert_root_node(root)?;

        let root = get_node_mut!(ef, &nid);
        root.attrib = crate::fs::EXFAT_ATTRIB_DIR;
        root.start_cluster = u32::from_le(ef.sb.rootdir_cluster);
        root.fptr_cluster = root.start_cluster;
        let valid_size = match ef.rootdir_size() {
            Ok(v) => v,
            Err(e) => {
                ef.remove_root_node()?;
                return Err(e.into());
            }
        };
        let root = get_node_mut!(ef, &nid);
        root.valid_size = valid_size;
        root.size = root.valid_size;
        // exFAT does not have time attributes for the root directory
        root.mtime = 0;
        root.atime = 0;
        // always keep at least 1 reference to the root node
        root.get();

        if let Err(e) = ef.cache_directory(nid) {
            get_node_mut!(ef, &nid).put();
            ef.reset_node()?;
            ef.remove_root_node()?;
            return Err(e);
        }
        if ef.upcase.is_empty() {
            println!("upcase table is not found");
            get_node_mut!(ef, &nid).put();
            ef.reset_node()?;
            ef.remove_root_node()?;
            return Err(crate::Error::Errno(EIO.into()));
        }
        if ef.cmap.chunk.is_empty() {
            println!("clusters bitmap is not found");
            get_node_mut!(ef, &nid).put();
            ef.reset_node()?;
            ef.remove_root_node()?;
            return Err(crate::Error::Errno(EIO.into()));
        }
        Ok(ef)
    }

    fn finalize_super_block(&mut self) -> crate::Result<()> {
        if self.ro != 0 {
            return Ok(());
        }
        self.sb.volume_state =
            (u16::from_le(self.sb.volume_state) & !crate::fs::EXFAT_STATE_MOUNTED).to_le();
        // Some implementations set the percentage of allocated space to 0xff
        // on FS creation and never update it. In this case leave it as is.
        if self.sb.allocated_percent != 0xff {
            let free = self.get_free_clusters()?;
            let total = u32::from_le(self.sb.cluster_count);
            self.sb.allocated_percent = (((total - free) * 100 + total / 2) / total)
                .try_into()
                .unwrap();
        }
        self.commit_super_block()
    }

    /// # Errors
    /// # Panics
    pub fn unmount(&mut self) -> crate::Result<()> {
        self.flush_nodes()?;
        self.flush()?;
        get_node_mut!(self, &crate::node::NID_ROOT).put();
        self.reset_node()?;
        self.dump_node_all();
        self.remove_root_node()?;
        self.finalize_super_block()?;
        // Rust
        match self.opt.nidalloc {
            crate::option::NidAllocMode::Linear => {
                assert!(self.imap.pool.is_empty());
                assert!(self.imap.chunk.is_empty());
            }
            crate::option::NidAllocMode::Bitmap => {
                log::debug!("imap: {} pool entries", self.imap.pool.len());
            }
        }
        Ok(())
    }

    /// # Errors
    pub fn stat(&self, nid: crate::node::Nid) -> crate::Result<Stat> {
        let Some(node) = self.nmap.get(&nid) else {
            return Err(crate::Error::Errno(ENOENT.into()));
        };
        let mode = if (node.attrib & crate::fs::EXFAT_ATTRIB_DIR) != 0 {
            S_IFDIR | (0o777 & !self.opt.dmask)
        } else {
            S_IFREG | (0o777 & !self.opt.fmask)
        };
        // There is no such thing as inode in exFAT, but since FUSE ops
        // in fuser are built around ino (which is usually inode#),
        // return nid as ino.
        Ok(Stat {
            st_dev: 0,
            st_ino: node.nid,
            st_nlink: 1,
            st_mode: mode,
            st_uid: self.opt.uid,
            st_gid: self.opt.gid,
            st_rdev: 0,
            st_size: node.size,
            st_blksize: 0,
            st_blocks: crate::util::round_up!(node.size, self.get_cluster_size()) / 512,
            st_atime: node.atime,
            st_mtime: node.mtime,
            // set ctime to mtime to ensure we don't break programs that rely on ctime
            // (e.g. rsync)
            st_ctime: node.mtime,
        })
    }

    // f_files, f_ffree are fake values because in exFAT there is
    // a) no simple way to count files;
    // b) no such thing as inode;
    // So here we assume that inode = cluster.
    /// # Errors
    /// # Panics
    pub fn statfs(&self) -> crate::Result<StatFs> {
        let cluster_size = self.get_cluster_size().try_into().unwrap();
        let free_clusters = self.get_free_clusters()?.into();
        Ok(StatFs {
            f_bsize: cluster_size,
            f_blocks: u64::from_le(self.sb.sector_count) >> self.sb.spc_bits,
            f_bfree: free_clusters,
            f_bavail: free_clusters,
            f_files: u32::from_le(self.sb.cluster_count).into(),
            f_ffree: free_clusters,
            f_namelen: NAME_MAX.try_into().unwrap(),
            f_frsize: cluster_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    #[allow(unreachable_code)]
    #[test]
    fn test_exfat_ask_to_fix() {
        return; // disabled
        loop {
            println!("enter y or Y");
            if super::Exfat::ask_to_fix_(&crate::option::RepairMode::Ask) {
                break;
            }
        }
        loop {
            println!("enter n or N");
            if !super::Exfat::ask_to_fix_(&crate::option::RepairMode::Ask) {
                break;
            }
        }
    }

    const EXFAT_DEBUG: &str = "EXFAT_DEBUG"; // option
    const EXFAT_DEVICE: &str = "EXFAT_DEVICE";
    const EXFAT_PATH: &str = "EXFAT_PATH";

    fn init_std_logger() -> Result<(), log::SetLoggerError> {
        let env = env_logger::Env::default().filter_or("RUST_LOG", "trace");
        env_logger::try_init_from_env(env)
    }

    fn read_all(ef: &mut super::Exfat, nid: crate::node::Nid) -> crate::Result<Vec<u8>> {
        let st = ef.stat(nid)?;
        let mut resid = st.st_size;
        let size = if resid / 10 > 0 { resid / 10 } else { resid };
        let mut offset = 0;
        let mut v = vec![];
        while resid > 0 {
            let b = ef.preadx(nid, size, offset)?;
            let n = u64::try_from(b.len()).unwrap();
            v.extend(b);
            offset += n;
            resid -= n;
        }
        assert_eq!(ef.preadx(nid, size, offset)?.len(), 0);
        Ok(v)
    }

    fn sha256(buf: &[u8]) -> Vec<u8> {
        let mut h = sha2::Sha256::new();
        h.update(buf);
        h.finalize()[..].to_vec()
    }

    fn test_exfat_path(ef: &mut super::Exfat, f: &str) {
        log::info!("{f}");
        match ef.lookup(f) {
            Ok(nid) => {
                log::info!("{nid}");
                match ef.stat(nid) {
                    Ok(st) => {
                        log::info!("{st:?}");
                        match st.st_mode & S_IFMT {
                            S_IFDIR => match ef.readdir(nid) {
                                Ok(v) => log::info!("{}: {v:?}", v.len()),
                                Err(e) => panic!("{e}"),
                            },
                            S_IFREG => {
                                let sum1 = match ef.read_all(nid) {
                                    Ok(v) => {
                                        assert_eq!(v.len(), st.st_size.try_into().unwrap());
                                        match libfs::string::b2s(&v) {
                                            Ok(v) => println!("{v}"),
                                            Err(e) => panic!("{e}"),
                                        }
                                        hex::encode(sha256(&v))
                                    }
                                    Err(e) => panic!("{e}"),
                                };
                                log::info!("sha256: {sum1}");
                                let sum2 = match read_all(ef, nid) {
                                    Ok(v) => {
                                        assert_eq!(v.len(), st.st_size.try_into().unwrap());
                                        match libfs::string::b2s(&v) {
                                            Ok(v) => println!("{v}"),
                                            Err(e) => panic!("{e}"),
                                        }
                                        hex::encode(sha256(&v))
                                    }
                                    Err(e) => panic!("{e}"),
                                };
                                log::info!("sha256: {sum2}");
                                assert_eq!(sum1, sum2);
                            }
                            x => panic!("{x:o}"),
                        }
                    }
                    Err(e) => panic!("{e}"),
                }
                get_node_mut!(ef, &nid).put();
            }
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn test_exfat_mount() {
        if let Ok(spec) = std::env::var(EXFAT_DEVICE) {
            let _ = init_std_logger();
            let mut args = vec!["--mode", "ro"];
            if std::env::var(EXFAT_DEBUG).is_ok() {
                args.push("--debug");
            }
            // mount
            let mut ef = match super::Exfat::mount(&spec, &args) {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            };
            // dump_node
            ef.dump_node_all();
            // statfs
            log::info!("{:?}", ef.statfs());
            // stat
            match ef.stat(crate::node::NID_ROOT) {
                Ok(v) => log::info!("{v:?}"),
                Err(e) => panic!("{e}"),
            }
            // lookup
            match ef.lookup("/") {
                Ok(v) => {
                    assert_eq!(v, crate::node::NID_ROOT);
                    get_node_mut!(ef, &v).put();
                }
                Err(e) => panic!("{e}"),
            }
            // read
            if let Err(e) = ef.preadx(crate::node::NID_ROOT, 1, 0) {
                panic!("{e}");
            }
            // env path
            if let Ok(f) = std::env::var(EXFAT_PATH) {
                test_exfat_path(&mut ef, &f);
            }
            // dump_node
            ef.dump_node_all();
            // unmount
            if let Err(e) = ef.unmount() {
                panic!("{e}");
            }
        }
    }
}
