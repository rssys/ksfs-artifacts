use core::assert;
use core::marker::Sized;

/// # Panics
#[must_use]
pub fn align_head_to<T>(buf: &[u8]) -> &T {
    let (prefix, body, _) = unsafe { buf.align_to::<T>() };
    assert!(prefix.is_empty(), "{:?} {}", prefix, prefix.len());
    &body[0]
}

/// # Panics
#[must_use]
pub fn align_to<T>(buf: &[u8]) -> &T {
    let (prefix, body, suffix) = unsafe { buf.align_to::<T>() };
    assert!(prefix.is_empty(), "{:?} {}", prefix, prefix.len());
    assert!(suffix.is_empty(), "{:?} {}", suffix, suffix.len());
    &body[0]
}

/// # Panics
pub fn align_head_to_mut<T>(buf: &mut [u8]) -> &mut T {
    let (prefix, body, _) = unsafe { buf.align_to_mut::<T>() };
    assert!(prefix.is_empty(), "{:?} {}", prefix, prefix.len());
    &mut body[0]
}

/// # Panics
pub fn align_to_mut<T>(buf: &mut [u8]) -> &mut T {
    let (prefix, body, suffix) = unsafe { buf.align_to_mut::<T>() };
    assert!(prefix.is_empty(), "{:?} {}", prefix, prefix.len());
    assert!(suffix.is_empty(), "{:?} {}", suffix, suffix.len());
    &mut body[0]
}

/// # Safety
pub fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts(
            core::ptr::from_ref::<T>(p).cast::<u8>(),
            ::core::mem::size_of::<T>(),
        )
    }
}
