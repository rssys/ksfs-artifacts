use crate::kernel::fs::BlockDevice;
use crate::kernel::kobj::{BufferHead, RsFile};

use crate::libc;

use crate::std::os::unix::io::*;
use crate::std::io;
use crate::std::os::unix::fs::*;

use core::cmp::min;

pub struct Disk {
    pub bdev: BlockDevice,
}

impl Disk {
    pub fn new(dev_name: &str, bsize: u64) -> Result<Self, i32> {
        Ok(Disk {
            bdev: BlockDevice::new(dev_name, bsize as u32)?,
        })
    }

    pub fn sync_all(&self) -> Result<(), i32> {
        self.bdev.sync_all()
    }

    pub fn sync_data(&self) -> Result<(), i32> {
        self.bdev.sync_data()
    }

    pub fn sync_block(&self, sector: u64) -> Result<(), libc::c_int> {
        self.bdev.sync_block(sector)
    }

    pub fn bread(&self, blockno: u64) -> Result<BufferHead, libc::c_int> {
        self.bdev.bread(blockno)
    }

    pub fn getblk(&self, blockno: u64) -> Result<BufferHead, libc::c_int> {
        self.bdev.getblk(blockno)
    }
}

impl AsRawFd for Disk {
    fn as_raw_fd(&self) -> RawFd {
        self.bdev.as_raw_fd()
    }
}

pub struct DiskFile {
    bdev: BlockDevice,
    bsize: u64,
}

impl DiskFile {
    pub fn new(dev_name: &str, bsize: u64) -> Result<Self, i32> {
        let bdev = BlockDevice::new(dev_name, bsize as u32)?;
        Ok(Self {
            bdev: bdev,
            bsize: bsize,
        })
    }

    pub fn sync_all(&self) -> Result<(), i32> {
        self.bdev.sync_all()
    }

    pub fn sync_data(&self) -> Result<(), i32> {
        self.bdev.sync_data()
    }

    pub fn sync_block(&self, sector: u64) {
        if let Ok(mut bh) = self.bdev.bread(sector) {
            bh.sync_dirty_buffer();
        }
    }

    pub fn get_size(&self) -> u64 {
        self.bdev.get_size()
    }
}

impl FileExt for DiskFile {
    fn read_at(&self, data: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut read = 0;
        while read < data.len() {
            let curr_off = offset as usize + read;
            let sector = curr_off / self.bsize as usize;
            let sector_off = curr_off % self.bsize as usize;
            let read_size = min(self.bsize as usize - sector_off, data.len() - read);

            let bh = self.bdev.bread(sector as u64)
                .map_err(|err| { io::Error::from_raw_os_error(err) })?;
            let b_slice = bh.data();
            let read_region = &b_slice[sector_off..sector_off+read_size];
            let data_region = &mut data[read..read+read_size];
            data_region.copy_from_slice(read_region);
            read += read_size;
        }
        Ok(read)
    }

    fn write_at(&self, data: &[u8], offset: u64) -> io::Result<usize> {
        let mut written = 0;
        while written < data.len() {
            let curr_off = offset as usize + written;
            let sector = curr_off / self.bsize as usize;
            let sector_off = curr_off % self.bsize as usize;
            let write_size = min(self.bsize as usize - sector_off, data.len() - written);

            let mut bh = self.bdev.bread(sector as u64)
                .map_err(|err| { io::Error::from_raw_os_error(err) })?;
            let b_slice = bh.data_mut();
            let write_region = &mut b_slice[sector_off..sector_off+write_size];
            let data_region = &data[written..written+write_size];
            write_region.copy_from_slice(data_region);
            bh.mark_buffer_dirty();
            written += write_size;
        }
        Ok(written)
    }
}

impl AsRawFd for DiskFile {
    fn as_raw_fd(&self) -> RawFd {
        self.bdev.as_raw_fd()
    }
}

pub struct KernelFile {
    file: RsFile,
    size: u64,
}

impl KernelFile {
    pub fn new(filename: &str, flags: i32, mode: u16) -> Result<Self, i32> {
        let file = RsFile::new(filename, flags, mode)?;
        let size = file.lseek(0, libc::SEEK_END)? as u64;
        file.lseek(0, libc::SEEK_SET);
        Ok(KernelFile {
            file: file,
            size: size
        })
    }

    pub fn fsync(&self, datasync: bool) -> Result<(), i32> {
        self.file.fsync(datasync)
    }

    pub fn get_size(&self) -> u64 {
        self.size
    }
}

impl FileExt for KernelFile {
    fn read_at(&self, data: &mut [u8], offset: u64) -> io::Result<usize> {
        let res = self.file.pread(data, offset);
        match res {
            Err(e) => Err(io::Error::from_raw_os_error(e)),
            Ok(size) => Ok(size)
        }
    }

    fn write_at(&self, data: &[u8], offset: u64) -> io::Result<usize> {
        let res = self.file.pwrite(data, offset);
        match res {
            Err(e) => Err(io::Error::from_raw_os_error(e)),
            Ok(size) => Ok(size)
        }
    }
}
