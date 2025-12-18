#![feature(lang_items)]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]
#![feature(alloc_layout_extra)]
#![feature(panic_info_message)]
#![feature(slice_fill)]
#![no_std]

#[macro_use]
extern crate alloc;
extern crate libexfat;
extern crate bento;
extern crate serde;

pub mod exfat;

use alloc::boxed::Box;

use bento::bento_utils::BentoFilesystem;
use exfat::ExfatFS;
use bento::println;

static mut EXFAT_FS: Option<&'static mut ExfatFS> = None;

#[no_mangle]
pub fn rust_main() {
    println!("Rust exfat loading\n");
    let exfat_fs = Box::new(ExfatFS::new());
    exfat_fs.register();
    let exfat_ref: &'static mut ExfatFS = Box::leak(exfat_fs);
    unsafe {EXFAT_FS = Some(exfat_ref);}
}

#[no_mangle]
pub fn rust_exit() {
    if let Some(s) = unsafe { EXFAT_FS.take() } {
        let exfat_fs = unsafe { Box::from_raw(s as *mut ExfatFS) };
        exfat_fs.unregister();
        drop(exfat_fs);
    }
}