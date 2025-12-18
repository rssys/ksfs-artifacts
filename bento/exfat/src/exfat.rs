#![feature(lang_items)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]
#![feature(alloc_layout_extra)]
#![feature(panic_info_message)]
#![feature(slice_fill)]
#![no_std]

use core::convert::TryInto;

#[macro_use]
use libexfat;
use bento::bento_utils;
use bento::bento_utils::*;
use bento::fuse::*;
use bento::std::ffi::OsStr;
use bento::println;
use bento::std::sync::*;
use serde::{Serialize, Deserialize};
use bento::libc as libc;
use bento::kernel::stat as stat;
use libexfat::device::{AsyncRead, AsyncWrite};

use alloc::string::String;
use alloc::string::ToString;
use alloc::boxed::Box;
use alloc::sync::Arc;

#[derive(Serialize, Deserialize)]
pub struct ExfatState {
}

pub struct ExfatFS {
    exfat: Option<Box<Mutex<libexfat::exfat::Exfat>>>,
    file: Option<Arc<KernelFile>>,
    op_lock: RwLock<()>,
}

impl ExfatFS {
    const NAME: &'static str = "bento_exfat\0";
    pub fn new() -> Self {
        ExfatFS {
            exfat: None,
            file: None,
            op_lock: RwLock::new(()),
        }
    }
}

const TTL: bento::time::Timespec = bento::time::Timespec::new(10, 0);

fn unix2ts(t: u64) -> bento::time::Timespec {
    bento::time::Timespec::new((t / 1000000000) as i64,
        (t % 1000000000) as i32)
}

fn mode2kind(mode: libexfat::exfat::StatMode) -> FileType {
    match mode & stat::S_IFMT {
        stat::S_IFDIR => FileType::Directory,
        stat::S_IFREG => FileType::RegularFile,
        _ => FileType::RegularFile,
    }
}

fn stat2attr(st: &libexfat::exfat::Stat) -> FileAttr {
    let mtime = unix2ts(st.st_mtime);
    FileAttr {
        ino: st.st_ino,
        size: st.st_size,
        blocks: st.st_blocks,
        atime: unix2ts(st.st_atime),
        mtime,
        ctime: mtime,
        crtime: mtime,
        kind: mode2kind(st.st_mode),
        perm: st.st_mode & 0o777,
        nlink: st.st_nlink,
        uid: st.st_uid,
        gid: st.st_gid,
        rdev: st.st_rdev,
        flags: 0,
    }
}

fn e2i(e: &libexfat::Error) -> i32 {
    (match e {
        libexfat::Error::Errno(e) => e.clone(),
        libexfat::Error::Error(e) => libc::EIO,
    }) as i32
}

macro_rules! get_exfat {
    ($exfat:expr) => {
        $exfat.as_ref().unwrap().lock().unwrap()
    };
}
macro_rules! get_exfat_or_err {
    ($exfat:expr, $reply: expr) => {
        if !$exfat.is_none() {
            $exfat.as_ref().unwrap().lock().unwrap()
        } else {
            $reply.error(libc::EIO);
            return;
        }
    };
}

macro_rules! get_node {
    ($ef:expr, $nid:expr) => {
        $ef.get_node($nid).unwrap()
    };
}

macro_rules! get_node_mut {
    ($ef:expr, $nid:expr) => {
        $ef.get_node_mut($nid).unwrap()
    };
}

extern "C" {
    fn get_module();
    fn put_module();
}

impl BentoFilesystem<'_,i32,ExfatState> for ExfatFS {
    fn get_name(&self) -> &'static str {
        Self::NAME
    }

    fn bento_init(
        &mut self,
        _req: &Request,
        devname: &OsStr,
        outarg: &mut FuseConnInfo,
    ) -> Result<(), i32> {
        unsafe { get_module(); }
        outarg.proto_major = BENTO_KERNEL_VERSION;
        outarg.proto_minor = BENTO_KERNEL_MINOR_VERSION;

        let mut max_readahead = u32::MAX;
        if outarg.max_readahead < max_readahead {
            max_readahead = outarg.max_readahead;
        }

        outarg.max_readahead = max_readahead;
        outarg.max_background = 0;
        outarg.congestion_threshold = 0;
        outarg.time_gran = 1;
        outarg.want |= bento_utils::consts::FUSE_WRITEBACK_CACHE;
        outarg.want |= bento_utils::consts::FUSE_BIG_WRITES;
        outarg.want &= !bento_utils::consts::FUSE_AUTO_INVAL_DATA;

        if self.exfat.is_none() {
            let devname_str = devname.to_str().unwrap();
            let file = Arc::new(KernelFile::new(devname_str,
                libc::O_RDWR|libc::O_LARGEFILE, 0)?);
            let disk_size = file.get_size();
            let device = libexfat::device::Device::new(&file,
                libexfat::option::OpenMode::Rw, disk_size);
            let opt = libexfat::option::Opt {
                mode: libexfat::option::OpenMode::Rw,
                repair: libexfat::option::RepairMode::Yes,
                noatime: true,
                dmask: 0,
                fmask: 0,
                uid: 0,
                gid: 0,
                nidalloc: libexfat::option::NidAllocMode::Linear,
                debug: false
            };
            let exfat = match libexfat::exfat::Exfat::mount(opt, device) {
                Ok(e) => e,
                Err(e) => {
                    return Err(e2i(&e))
                },
            };
            self.exfat = Some(Box::new(Mutex::new(exfat)));
            self.file = Some(Arc::clone(&file));
        }
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat!(self.exfat);
        if let Err(e) = exfat.soil_super_block() {
            return Err(e2i(&e));
        }

        return Ok(());
    }

    fn bento_destroy(&mut self, _req: &Request) {
        if self.exfat.is_none() {
            unsafe { put_module(); }
            return;
        }
        {
            let mut exfat = get_exfat!(self.exfat);
            exfat.unmount();
        }
        self.exfat = None;
        unsafe { put_module(); }
    }

    fn bento_lookup(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let ino = match exfat.lookup_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        let st = match exfat.stat(ino) {
            Ok(v) => v,
            Err(e) => {
                get_node_mut!(exfat, ino).put();
                reply.error(e2i(&e));
                return;
            }
        };
        get_node_mut!(exfat, ino).put();
        reply.entry(&TTL, &stat2attr(&st), 0);
    }

    fn bento_getattr(&self, _req: &Request, ino: u64, reply: ReplyAttr) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let st = match exfat.stat(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        reply.attr(&TTL, &stat2attr(&st));
    }

    fn bento_setattr(
        &self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<bento::time::Timespec>,
        mtime: Option<bento::time::Timespec>,
        _fh: Option<u64>,
        crtime: Option<bento::time::Timespec>,
        chgtime: Option<bento::time::Timespec>,
        _bkuptime: Option<bento::time::Timespec>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let mut st = match exfat.stat(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        if let Some(mode) = mode {
            let mode_mask =
                stat::S_IFREG | stat::S_IFDIR | stat::S_IRWXU | stat::S_IRWXG | stat::S_IRWXO;
            let valid_mode_mask = mode_mask as u32;
            if (mode & !valid_mode_mask) != 0 {
                reply.error(libc::EPERM);
                return;
            }
        }
        if let Some(uid) = uid {
            if uid != st.st_uid {
                reply.error(libc::EPERM);
                return;
            }
        }
        if let Some(gid) = gid {
            if gid != st.st_gid {
                reply.error(libc::EPERM);
                return;
            }
        }
        if let Some(size) = size {
            get_node_mut!(exfat, ino).get();
            if let Err(e) = exfat.truncate(ino, size, true) {
                if exfat.flush_node(ino).is_err() {
                    // ignore this error
                }
                get_node_mut!(exfat, ino).put();
                reply.error(e2i(&e));
                return;
            }
            if let Err(e) = exfat.flush_node(ino) {
                get_node_mut!(exfat, ino).put();
                reply.error(e2i(&e));
                return;
            }
            // truncate has updated mtime
            st = match exfat.stat(ino) {
                Ok(v) => v,
                Err(e) => {
                    get_node_mut!(exfat, ino).put();
                    reply.error(e2i(&e));
                    return;
                }
            };
            get_node_mut!(exfat, ino).put();
            st.st_size = size;
        }
        let mut attr = stat2attr(&st);
        if let Some(atime) = atime {
            attr.atime = atime
        }
        if let Some(mtime) = mtime {
            attr.mtime = mtime
        }
        if let Some(chgtime) = chgtime {
            attr.ctime = chgtime;
        }
        if let Some(crtime) = crtime {
            attr.crtime = crtime;
        }
        reply.attr(&TTL, &attr);
    }

    fn bento_mknod(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let nid = match exfat.mknod_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        let st = match exfat.stat(nid) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        reply.entry(&TTL, &stat2attr(&st), 0);
    }

    fn bento_mkdir(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        reply: ReplyEntry,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let nid = match exfat.mkdir_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        let st = match exfat.stat(nid) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        reply.entry(&TTL, &stat2attr(&st), 0);
    }

    fn bento_unlink(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let ino = match exfat.lookup_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        if let Err(e) = exfat.unlink(ino) {
            if let Some(node) = exfat.get_node_mut(ino) {
                node.put();
            }
            reply.error(e2i(&e));
            return;
        }
        reply.ok();
    }

    fn bento_rmdir(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let ino = match exfat.lookup_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        if let Err(e) = exfat.rmdir(ino) {
            if let Some(node) = exfat.get_node_mut(ino) {
                node.put();
            }
            reply.error(e2i(&e));
            return;
        }
        reply.ok();
    }

    fn bento_rename(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let Some(newname) = newname.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        if let Err(e) = exfat.rename_at(parent, name, newparent, newname) {
            reply.error(e2i(&e));
            return;
        }
        reply.ok();
    }

    fn bento_open(
        &self,
        _req: &Request,
        ino: u64,
        flags: u32,
        reply: ReplyOpen,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(node) = exfat.get_node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        assert_eq!(node.get_nid(), ino);
        get_node_mut!(exfat, ino).get(); // put on release

        // https://docs.rs/fuser/latest/fuser/trait.Filesystem.html#method.open
        // says "Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and O_TRUNC)
        // are available in flags.".
        if (flags & libc::O_TRUNC as u32) != 0 {
            if let Err(e) = exfat.truncate(ino, 0, true) {
                reply.error(e2i(&e));
                return;
            }
        }
        reply.opened(ino, bento::fuse::consts::FOPEN_KEEP_CACHE);
    }

    fn bento_read(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        let mut buf = vec![0; size as usize];
        let op_guard = self.op_lock.read().unwrap();
        let mut async_read = AsyncRead::new(self.file.as_ref().unwrap(), &mut buf);
        let mut bytes: u64;
        {
            let mut exfat = get_exfat_or_err!(self.exfat, reply);
            assert_eq!(ino, fh);
            bytes = match exfat.pread_async(ino, offset as u64, &mut async_read) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(e2i(&e));
                    return;
                }
            };
        };
        if let Err(_) = async_read.execute() {
            reply.error(libc::EIO);
            return;
        }
        reply.data(&buf[..bytes.try_into().unwrap()]);
    }

    fn bento_write(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        flags: u32,
        reply: ReplyWrite,
    ) {
        let op_guard = self.op_lock.read().unwrap();
        let mut async_write = AsyncWrite::new(self.file.as_ref().unwrap(), data);
        let mut bytes: u64;
        {
            let mut exfat = get_exfat_or_err!(self.exfat, reply);
            assert_eq!(ino, fh);
            bytes = match exfat.pwrite_async(ino, offset as u64, &mut async_write) {
                Ok(v) => v,
                Err(e) => {
                    reply.error(e2i(&e));
                    return;
                }
            };
        };
        if let Err(_) = async_write.execute() {
            reply.error(libc::EIO);
            return;
        }
        reply.written(bytes.try_into().unwrap());
    }

    fn bento_flush(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        assert_eq!(ino, fh);
        if let Err(e) = exfat.flush_node(ino) {
            reply.error(e2i(&e));
            return;
        }
        reply.ok();
    }

    fn bento_release(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        flags: u32,
        _lock_owner: u64,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        assert_eq!(ino, fh);
        if let Err(e) = exfat.flush_node(ino) {
            reply.error(e2i(&e));
            return;
        }
        get_node_mut!(exfat, ino).put();
        reply.ok();
    }

    fn bento_fsync(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        assert_eq!(ino, fh);
        if let Err(e) = exfat.flush_nodes() {
            reply.error(e2i(&e));
            return;
        }
        if let Err(e) = exfat.flush() {
            reply.error(e2i(&e));
            return;
        }
        // libexfat's fsync is to fsync device fd, not to fsync this ino...
        if let Err(e) = exfat.fsync() {
            reply.error(e2i(&e));
            return;
        }
        reply.ok();
    }

    fn bento_opendir(
        &self,
        _req: &Request,
        ino: u64,
        _flags: u32,
        reply: ReplyOpen,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(node) = exfat.get_node(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        assert_eq!(node.get_nid(), ino);
        get_node_mut!(exfat, ino).get(); // put on releasedir
        reply.opened(ino, bento::fuse::consts::FOPEN_KEEP_CACHE);
    }

    fn bento_readdir(
        &self,
        _req: &Request,
        dino: u64,
        fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        assert_eq!(dino, fh);
        let Some(dnode) = exfat.get_node(dino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if !dnode.is_directory() {
            reply.error(libc::ENOTDIR);
            return;
        }

        let mut offset = offset;
        if offset < 1 {
            if reply.add(dnode.get_nid(), 1, FileType::Directory, ".") {
                reply.ok();
                return;
            }
            offset += 1;
        }
        if offset < 2 {
            if reply.add(dnode.get_pnid(), 2, FileType::Directory, "..") {
                reply.ok();
                return;
            }
            offset += 1;
        }

        let mut c = match exfat.opendir_cursor(dino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        let mut next = 3;
        loop {
            let ino = match exfat.readdir_cursor(&mut c) {
                Ok(v) => v,
                Err(e) => {
                    if let libexfat::Error::Errno(e) = e {
                        if e == libc::ENOENT {
                            break;
                        }
                    }
                    exfat.closedir_cursor(c);
                    reply.error(e2i(&e));
                    return;
                }
            };
            if offset < next {
                let node = get_node!(exfat, ino);
                let st = match exfat.stat(ino) {
                    Ok(v) => v,
                    Err(e) => {
                        get_node_mut!(exfat, ino).put();
                        exfat.closedir_cursor(c);
                        reply.error(e2i(&e));
                        return;
                    }
                };
                if reply.add(
                    st.st_ino,
                    next,
                    mode2kind(st.st_mode),
                    node.get_name(),
                ) {
                    get_node_mut!(exfat, ino).put();
                    break;
                }
                offset += 1;
            }
            get_node_mut!(exfat, ino).put();
            next += 1;
        }
        exfat.closedir_cursor(c);
        reply.ok();
    }

    fn bento_releasedir(
        &self,
        _req: &Request,
        ino: u64,
        fh: u64,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        assert_eq!(ino, fh);
        get_node_mut!(exfat, ino).put();
        reply.ok();
    }

    fn bento_fsyncdir(
        &self,
        req: &Request,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.bento_fsync(req, ino, fh, datasync, reply);
    }

    fn bento_statfs(&self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        match exfat.statfs() {
            Ok(v) => reply.statfs(
                v.f_blocks,
                v.f_bfree,
                v.f_bavail,
                v.f_files,
                v.f_ffree,
                v.f_bsize,
                v.f_namelen,
                v.f_frsize,
            ),
            Err(e) => reply.error(e2i(&e)),
        }
    }

    fn bento_create(
        &self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _flags: u32,
        reply: ReplyCreate,
    ) {
        let op_guard = self.op_lock.write().unwrap();
        let mut exfat = get_exfat_or_err!(self.exfat, reply);
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let ino = match exfat.mknod_at(parent, name) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        get_node_mut!(exfat, ino).get(); // put on release
        let st = match exfat.stat(ino) {
            Ok(v) => v,
            Err(e) => {
                reply.error(e2i(&e));
                return;
            }
        };
        reply.created(&TTL, &stat2attr(&st), 0, ino, 0);
    }
}
