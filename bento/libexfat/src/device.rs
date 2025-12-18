use bento::std::os::unix::fs::FileExt;
use bento::std as std;
use std::io::Read;
use std::io::Write;
use std::io::Result;
use alloc::vec::Vec;
use alloc::sync::Arc;
use bento::bento_utils::KernelFile;
use bento::libc as libc;

pub struct Device {
    fp: Arc<KernelFile>,
    mode: crate::option::OpenMode,
    size: u64
}

pub struct ReadOperation {
    size: usize,
    offset: u64
}

pub struct WriteOperation {
    size: usize,
    offset: u64
}

pub struct AsyncRead<'a> {
    operations: Vec<ReadOperation>,
    file: Arc<KernelFile>,
    pub(crate) buf: &'a mut [u8],
    pub(crate) buf_size: usize,
    fill_zero_from: Option<usize>,
}

pub struct AsyncWrite<'a> {
    operations: Vec<WriteOperation>,
    file: Arc<KernelFile>,
    pub(crate) buf: &'a [u8],
    pub(crate) buf_size: usize,
}

impl AsyncRead<'_> {
    pub fn new<'a>(file: &Arc<KernelFile>, buf: &'a mut [u8]) -> AsyncRead<'a> {
        let size = buf.len();
        AsyncRead {
            operations: Vec::new(),
            file: Arc::clone(file),
            buf: buf,
            buf_size: size,
            fill_zero_from: None,
        }
    }

    pub fn fill_zero(&mut self, from: usize) {
        self.fill_zero_from = Some(from);
    }
    pub fn execute(&mut self) -> std::io::Result<()> {
        let mut i: usize = 0;
        for op in &mut self.operations {
            let buf = &mut self.buf[i..(i + op.size)];
            i += op.size;
            let usize = self.file.read_at(buf, op.offset)?;
            if usize != buf.len() {
                return Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
        if let Some(from) = self.fill_zero_from {
            for i in from..self.buf.len() {
                self.buf[i] = 0;
            }
        }
        Ok(())
    }
}

impl AsyncWrite<'_> {
    pub fn new<'a>(file: &Arc<KernelFile>, buf: &'a [u8]) -> AsyncWrite<'a> {
        let size = buf.len();
        AsyncWrite {
            operations: Vec::new(),
            file: Arc::clone(file),
            buf: buf,
            buf_size: size,
        }
    }

    pub fn execute(&self) -> std::io::Result<()> {
        let i: usize = 0;
        for op in &self.operations {
            let buf = &self.buf[i..(i + op.size)];
            let usize = self.file.write_at(buf, op.offset)?;
            if usize != buf.len() {
                return Err(std::io::Error::from_raw_os_error(libc::EIO))
            }
        }
        Ok(())
    }
}

impl Device {
    pub fn new(file: &Arc<KernelFile>, mode: crate::option::OpenMode,
        size: u64) -> Self {
        Device {
            fp: Arc::clone(file),
            mode: mode,
            size: size,
        }
    }

    pub fn new_async_read<'a>(&self, buf: &'a mut [u8]) -> AsyncRead<'a> {
        let len = buf.len();
        AsyncRead {
            operations: Vec::new(),
            file: Arc::clone(&self.fp),
            buf: buf,
            buf_size: len,
            fill_zero_from: None,
        }
    }

    pub fn new_async_write<'a>(&self, buf: &'a [u8]) -> AsyncWrite<'a> {
        AsyncWrite {
            operations: Vec::new(),
            file: Arc::clone(&self.fp),
            buf: buf,
            buf_size: buf.len(),
        }
    }

    pub fn fsync(&mut self) -> crate::Result<()> {
        Ok(self.fp.fsync(false)?)
    }

    pub(crate) fn get_mode(&self) -> crate::option::OpenMode {
        self.mode
    }

    #[must_use]
    pub fn get_size(&self) -> u64 {
        self.size
    }
    pub fn pread(&mut self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        self.fp.read_exact_at(buf, offset)
    }
    pub fn pread_async(&mut self, size: usize, offset: u64, async_read: &mut AsyncRead) -> std::io::Result<()> {
        async_read.operations.push(ReadOperation {
            size:size,
            offset: offset
        });
        Ok(())
    }

    pub fn pwrite(&mut self, buf: &[u8], offset: u64) -> std::io::Result<()> {
        self.fp.write_all_at(buf, offset)
    }
    pub fn pwrite_async(&mut self,size: usize, offset: u64, async_write: &mut AsyncWrite) -> std::io::Result<()> {
        async_write.operations.push(WriteOperation {
            size: size,
            offset: offset
        });
        Ok(())
    }

    pub fn preadx(&mut self, size: u64, offset: u64) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0; size.try_into().unwrap()];
        self.pread(&mut buf, offset)?;
        Ok(buf)
    }
}
