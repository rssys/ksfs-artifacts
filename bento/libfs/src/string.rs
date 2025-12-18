use core::result::Result;
use core::iter::Iterator;
use alloc::string::{String, ToString};
use core::option::Option::*;

#[allow(unused_macros)]
#[macro_export]
macro_rules! new_cstring {
    ($s:expr) => {
        std::ffi::CString::new($s)
    };
}
pub use new_cstring;

/// # Errors
pub fn b2s(b: &[u8]) -> Result<String, core::str::Utf8Error> {
    let s = core::str::from_utf8(
        match b.iter().position(|&x| x == 0) {
            Some(v) => &b[..v],
            None => b,
        },
    )?;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_b2s() {
        assert_eq!(
            super::b2s(&[104, 97, 109, 109, 101, 114, 50]),
            Ok("hammer2".to_string())
        );
        assert_eq!(
            super::b2s(&[104, 97, 109, 109, 101, 114, 50, 0]),
            Ok("hammer2".to_string())
        );
        assert_eq!(
            super::b2s(&[104, 97, 109, 109, 101, 114, 50, 0, 0]),
            Ok("hammer2".to_string())
        );

        assert_eq!(super::b2s(&[]), Ok(String::new()));
        assert_eq!(super::b2s(&[0]), Ok(String::new()));
        assert_eq!(super::b2s(&[0, 0]), Ok(String::new()));
        assert_eq!(
            super::b2s(&[0, 0, 104, 97, 109, 109, 101, 114, 50]),
            Ok(String::new())
        );
    }
}
