#![no_std]
pub mod device;
pub mod exfat;
mod extra;
pub mod fs;
pub mod node;
pub mod option;
mod time;
pub mod utf;
pub mod util;

use core::result::*;

use bento::std as std;

#[macro_use]
extern crate alloc;

pub const VERSION: [i32; 3] = [
    1, 4, 0, // from relan/exfat: libexfat/config.h:#define VERSION "1.4.0"
];

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Error(std::io::Error),
    Errno(i32)
}

impl From<i32> for Error {
    fn from(errno: i32) -> Self {
        Error::Errno(errno)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Error(e)
    }
}
