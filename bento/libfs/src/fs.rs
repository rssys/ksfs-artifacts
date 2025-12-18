use alloc::vec::Vec;
use alloc::string::String;

#[must_use]
pub fn join_path(f1: &str, f2: &str) -> Option<String> {
    let f1 = if f1.len() == 1 {
        f1
    } else {
        f1.trim_end_matches('/')
    };
    let f2 = f2.trim_matches('/');
    Some(format!("{}/{}", f1, f2))
}

#[must_use]
pub fn split_path(path: &str) -> Vec<&str> {
    let mut v = vec![];
    for x in &path.trim_matches('/').split('/').collect::<Vec<&str>>() {
        // multiple /'s between components generates ""
        if !x.is_empty() && *x != "." {
            v.push(*x);
        }
    }
    v
}
