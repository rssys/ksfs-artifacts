#[allow(unused_macros)]
#[macro_export]
macro_rules! div_round_up {
    ($x:expr, $d:expr) => {
        $x.div_ceil($d)
    };
}
pub use div_round_up;

#[allow(unused_macros)]
#[macro_export]
macro_rules! round_up {
    ($x:expr, $d:expr) => {
        $crate::div_round_up!($x, $d) * $d
    };
}
pub use round_up;

// div_floor is nightly-only as of 1.84.1
#[allow(unused_macros)]
#[macro_export]
macro_rules! div_round_down {
    ($x:expr, $d:expr) => {
        $x / $d
    };
}
pub use div_round_down;

#[allow(unused_macros)]
#[macro_export]
macro_rules! round_down {
    ($x:expr, $d:expr) => {
        $crate::div_round_down!($x, $d) * $d
    };
}
pub use round_down;

fn add_checksum_byte(sum: u16, byte: u8) -> u16 {
    (u32::from(sum.rotate_right(1)) + u32::from(byte)) as u16
}

fn add_checksum_bytes(sum: u16, buf: &[u8], n: usize) -> u16 {
    let mut sum = sum;
    for b in buf.iter().take(n) {
        sum = add_checksum_byte(sum, *b);
    }
    sum
}

// relan/exfat takes exfat_entry_meta1*
fn start_checksum(entry: &crate::fs::ExfatEntry) -> u16 {
    let buf: &[u8; crate::fs::EXFAT_ENTRY_SIZE] = bytemuck::cast_ref(entry);
    let mut sum = 0;
    for (i, b) in buf.iter().enumerate() {
        // skip checksum field itself
        if i != 2 && i != 3 {
            sum = add_checksum_byte(sum, *b);
        }
    }
    sum
}

fn add_checksum(entry: &[u8], sum: u16) -> u16 {
    add_checksum_bytes(sum, entry, crate::fs::EXFAT_ENTRY_SIZE)
}

pub(crate) fn calc_checksum(entries: &[crate::fs::ExfatEntry], n: usize) -> u16 {
    let mut checksum = start_checksum(&entries[0]);
    for x in entries.iter().take(n).skip(1) {
        let buf: &[u8; crate::fs::EXFAT_ENTRY_SIZE] = bytemuck::cast_ref(x);
        checksum = add_checksum(buf, checksum);
    }
    checksum.to_le()
}

/// # Panics
#[must_use]
pub fn vbr_start_checksum(sector: &[u8], size: u64) -> u32 {
    let mut sum = 0u32;
    for (i, x) in sector.iter().enumerate().take(size.try_into().unwrap()) {
        // skip volume_state and allocated_percent fields
        if i != 0x6a && i != 0x6b && i != 0x70 {
            sum = sum.rotate_right(1) + u32::from(*x);
        }
    }
    sum
}

/// # Panics
#[must_use]
pub fn vbr_add_checksum(sector: &[u8], size: u64, sum: u32) -> u32 {
    let mut sum = sum;
    for x in sector.iter().take(size.try_into().unwrap()) {
        sum = sum.rotate_right(1) + u32::from(*x);
    }
    sum
}

pub(crate) fn calc_name_hash(upcase: &[u16], name: &[u16], length: usize) -> u16 {
    let mut hash = 0u16;
    for x in name.iter().take(length) {
        let c = u16::from_le(*x);
        // convert to upper case
        let c = upcase[usize::from(c)];
        hash = hash.rotate_right(1) + (c & 0xff);
        hash = hash.rotate_right(1) + (c >> 8);
    }
    hash.to_le()
}

