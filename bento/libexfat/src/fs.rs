use alloc::vec::Vec;

pub const EXFAT_FIRST_DATA_CLUSTER: u32 = 2;
pub const EXFAT_LAST_DATA_CLUSTER: u32 = 0xffff_fff6;

pub const EXFAT_CLUSTER_FREE: u32 = 0; // free cluster
pub const EXFAT_CLUSTER_BAD: u32 = 0xffff_fff7; // cluster contains bad sector
pub const EXFAT_CLUSTER_END: u32 = 0xffff_ffff; // final cluster of file or directory

pub const EXFAT_STATE_MOUNTED: u16 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExfatSuperBlock {
    pub jump: [u8; 3],             // 0x00 jmp and nop instructions
    pub oem_name: [u8; 8],         // 0x03 "EXFAT   "
    pub unused1: [u8; 53],         // 0x0B always 0
    pub sector_start: u64,         // 0x40 partition first sector
    pub sector_count: u64,         // 0x48 partition sectors count
    pub fat_sector_start: u32,     // 0x50 FAT first sector
    pub fat_sector_count: u32,     // 0x54 FAT sectors count
    pub cluster_sector_start: u32, // 0x58 first cluster sector
    pub cluster_count: u32,        // 0x5C total clusters count
    pub rootdir_cluster: u32,      // 0x60 first cluster of the root dir
    pub volume_serial: u32,        // 0x64 volume serial number
    pub version_minor: u8,         // 0x68 FS version
    pub version_major: u8,         // 0x69 FS version
    pub volume_state: u16,         // 0x6A volume state flags
    pub sector_bits: u8,           // 0x6C sector size as (1 << n)
    pub spc_bits: u8,              // 0x6D sectors per cluster as (1 << n)
    pub fat_count: u8,             // 0x6E always 1
    pub drive_no: u8,              // 0x6F always 0x80
    pub allocated_percent: u8,     // 0x70 percentage of allocated space
    pub unused2: [u8; 397],        // 0x71 always 0
    pub boot_signature: u16,       // the value of 0xAA55
}

impl Default for ExfatSuperBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl ExfatSuperBlock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            jump: [0; 3],
            oem_name: [0; 8],
            unused1: [0; 53],
            sector_start: 0,
            sector_count: 0,
            fat_sector_start: 0,
            fat_sector_count: 0,
            cluster_sector_start: 0,
            cluster_count: 0,
            rootdir_cluster: 0,
            volume_serial: 0,
            version_minor: 0,
            version_major: 0,
            volume_state: 0,
            sector_bits: 0,
            spc_bits: 0,
            fat_count: 0,
            drive_no: 0,
            allocated_percent: 0,
            unused2: [0; 397],
            boot_signature: 0,
        }
    }
}

pub const EXFAT_ENTRY_VALID: u8 = 0x80;
pub const EXFAT_ENTRY_CONTINUED: u8 = 0x40;
pub const EXFAT_ENTRY_OPTIONAL: u8 = 0x20;

pub const EXFAT_ENTRY_BITMAP: u8 = 0x01 | EXFAT_ENTRY_VALID;
pub const EXFAT_ENTRY_UPCASE: u8 = 0x02 | EXFAT_ENTRY_VALID;
pub const EXFAT_ENTRY_LABEL: u8 = 0x03 | EXFAT_ENTRY_VALID;
pub const EXFAT_ENTRY_FILE: u8 = 0x05 | EXFAT_ENTRY_VALID;
pub const EXFAT_ENTRY_FILE_INFO: u8 = EXFAT_ENTRY_VALID | EXFAT_ENTRY_CONTINUED;
pub const EXFAT_ENTRY_FILE_NAME: u8 = 0x01 | EXFAT_ENTRY_VALID | EXFAT_ENTRY_CONTINUED;
pub const EXFAT_ENTRY_FILE_TAIL: u8 =
    EXFAT_ENTRY_VALID | EXFAT_ENTRY_CONTINUED | EXFAT_ENTRY_OPTIONAL;

// common container for all entries
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntry {
    pub typ: u8, // any of EXFAT_ENTRY_xxx
    pub data: [u8; 31],
}

impl ExfatEntry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    #[must_use]
    pub fn bulk_new(n: usize) -> Vec<Self> {
        let mut entries = vec![];
        for _ in 0..n {
            entries.push(ExfatEntry::new());
        }
        entries
    }
}

// allocated clusters bitmap
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryBitmap {
    pub typ: u8, // EXFAT_ENTRY_BITMAP
    pub unknown1: [u8; 19],
    pub start_cluster: u32,
    pub size: u64, // in bytes
}

impl ExfatEntryBitmap {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

pub const EXFAT_UPCASE_CHARS: usize = 0x10000;

// upper case translation table
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryUpcase {
    pub typ: u8, // EXFAT_ENTRY_UPCASE
    pub unknown1: [u8; 3],
    pub checksum: u32,
    pub unknown2: [u8; 12],
    pub start_cluster: u32,
    pub size: u64, // in bytes
}

impl ExfatEntryUpcase {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

pub const EXFAT_ENAME_MAX: usize = 15;

// volume label
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryLabel {
    pub typ: u8,                      // EXFAT_ENTRY_LABEL
    pub length: u8,                   // number of characters
    pub name: [u16; EXFAT_ENAME_MAX], // in UTF-16LE
}

impl ExfatEntryLabel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

pub const EXFAT_ATTRIB_RO: u16 = 0x01;
pub const EXFAT_ATTRIB_HIDDEN: u16 = 0x02;
pub const EXFAT_ATTRIB_SYSTEM: u16 = 0x04;
pub const EXFAT_ATTRIB_VOLUME: u16 = 0x08;
pub const EXFAT_ATTRIB_DIR: u16 = 0x10;
pub const EXFAT_ATTRIB_ARCH: u16 = 0x20;

// file or directory info (part 1)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryMeta1 {
    pub typ: u8, // EXFAT_ENTRY_FILE
    pub continuations: u8,
    pub checksum: u16,
    pub attrib: u16, // combination of EXFAT_ATTRIB_xxx
    pub unknown1: u16,
    pub crtime: u16,    // creation time
    pub crdate: u16,    // creation date
    pub mtime: u16,     // latest modification time
    pub mdate: u16,     // latest modification date
    pub atime: u16,     // latest access time
    pub adate: u16,     // latest access date
    pub crtime_cs: u8,  // creation time in cs (centiseconds)
    pub mtime_cs: u8,   // latest modification time in cs
    pub crtime_tzo: u8, // timezone offset encoded
    pub mtime_tzo: u8,  // timezone offset encoded
    pub atime_tzo: u8,  // timezone offset encoded
    pub unknown2: [u8; 7],
}

pub const EXFAT_FLAG_ALWAYS1: u8 = 1 << 0;
pub const EXFAT_FLAG_CONTIGUOUS: u8 = 1 << 1;

// file or directory info (part 2)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryMeta2 {
    pub typ: u8,   // EXFAT_ENTRY_FILE_INFO
    pub flags: u8, // combination of EXFAT_FLAG_xxx
    pub unknown1: u8,
    pub name_length: u8,
    pub name_hash: u16,
    pub unknown2: u16,
    pub valid_size: u64, // in bytes, less or equal to size
    pub unknown3: [u8; 4],
    pub start_cluster: u32,
    pub size: u64, // in bytes
}

// file or directory name
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ExfatEntryName {
    pub typ: u8, // EXFAT_ENTRY_FILE_NAME
    pub unknown: u8,
    pub name: [u16; EXFAT_ENAME_MAX], // in UTF-16LE
}

pub const EXFAT_SUPER_BLOCK_SIZE: usize = core::mem::size_of::<ExfatSuperBlock>();
pub const EXFAT_ENTRY_SIZE: usize = core::mem::size_of::<ExfatEntry>();
pub const EXFAT_CLUSTER_SIZE: usize = core::mem::size_of::<u32>();

pub const EXFAT_SUPER_BLOCK_SIZE_U64: u64 = EXFAT_SUPER_BLOCK_SIZE as u64;
pub const EXFAT_ENTRY_SIZE_U64: u64 = EXFAT_ENTRY_SIZE as u64;
pub const EXFAT_CLUSTER_SIZE_U64: u64 = EXFAT_CLUSTER_SIZE as u64;

#[cfg(test)]
mod tests {
    #[test]
    fn test_struct_exfat_superblock() {
        assert_eq!(core::mem::size_of::<super::ExfatSuperBlock>(), 512);
    }

    #[test]
    fn test_const_exfat_superblock() {
        assert_eq!(
            super::EXFAT_SUPER_BLOCK_SIZE,
            match super::EXFAT_SUPER_BLOCK_SIZE_U64.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );
        assert_eq!(
            super::EXFAT_SUPER_BLOCK_SIZE_U64,
            match super::EXFAT_SUPER_BLOCK_SIZE.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );

        assert_eq!(
            super::EXFAT_SUPER_BLOCK_SIZE,
            core::mem::size_of::<super::ExfatSuperBlock>()
        );
    }

    #[test]
    fn test_struct_exfat_entry() {
        assert_eq!(core::mem::size_of::<super::ExfatEntry>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryBitmap>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryUpcase>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryLabel>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryMeta1>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryMeta2>(), 32);
        assert_eq!(core::mem::size_of::<super::ExfatEntryName>(), 32);
    }

    #[test]
    fn test_const_exfat_entry() {
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            match super::EXFAT_ENTRY_SIZE_U64.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE_U64,
            match super::EXFAT_ENTRY_SIZE.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );

        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntry>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryBitmap>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryUpcase>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryLabel>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryMeta1>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryMeta2>()
        );
        assert_eq!(
            super::EXFAT_ENTRY_SIZE,
            core::mem::size_of::<super::ExfatEntryName>()
        );
    }

    #[test]
    fn test_const_exfat_cluster() {
        assert_eq!(
            super::EXFAT_CLUSTER_SIZE,
            match super::EXFAT_CLUSTER_SIZE_U64.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );
        assert_eq!(
            super::EXFAT_CLUSTER_SIZE_U64,
            match super::EXFAT_CLUSTER_SIZE.try_into() {
                Ok(v) => v,
                Err(e) => panic!("{e}"),
            }
        );
    }

    #[test]
    fn test_slice_align_to() {
        let src: [u8; super::EXFAT_ENTRY_SIZE] = [
            123, // typ
            234, // length
            0, 0, // name[0] in le
            1, 0, // name[1] in le
            2, 0, // name[2] in le
            3, 0, // name[3] in le
            4, 0, // name[4] in le
            5, 0, // name[5] in le
            6, 0, // name[6] in le
            7, 0, // name[7] in le
            8, 0, // name[8] in le
            9, 0, // name[9] in le
            10, 0, // name[10] in le
            11, 0, // name[11] in le
            12, 0, // name[12] in le
            13, 0, // name[13] in le
            14, 0, // name[14] in le
        ];

        let (prefix, body, suffix) = unsafe { src.align_to::<super::ExfatEntryLabel>() };
        assert!(prefix.is_empty());
        assert!(suffix.is_empty());

        let dst = body[0];
        assert_eq!(dst.typ, 123);
        assert_eq!(dst.length, 234);
        assert_eq!(
            dst.name,
            [
                u16::from_le(0),
                u16::from_le(1),
                u16::from_le(2),
                u16::from_le(3),
                u16::from_le(4),
                u16::from_le(5),
                u16::from_le(6),
                u16::from_le(7),
                u16::from_le(8),
                u16::from_le(9),
                u16::from_le(10),
                u16::from_le(11),
                u16::from_le(12),
                u16::from_le(13),
                u16::from_le(14)
            ]
        );

        // dst is a copy of body[0]
        assert_ne!(
            format!("{:p}", core::ptr::addr_of!(src)),
            format!("{:p}", core::ptr::addr_of!(dst))
        );
        assert_eq!(
            format!("{:p}", core::ptr::addr_of!(src)),
            format!("{:p}", core::ptr::addr_of!(body[0]))
        );
    }

    #[test]
    fn test_struct_transmute() {
        let mut src = super::ExfatEntryLabel::new();
        assert_eq!(src.typ, 0);
        assert_eq!(src.length, 0);
        assert_eq!(src.name, [0; 15]);

        src.typ = 123;
        src.length = 234;
        src.name = [
            0_u16.to_le(),
            1_u16.to_le(),
            2_u16.to_le(),
            3_u16.to_le(),
            4_u16.to_le(),
            5_u16.to_le(),
            6_u16.to_le(),
            7_u16.to_le(),
            8_u16.to_le(),
            9_u16.to_le(),
            10_u16.to_le(),
            11_u16.to_le(),
            12_u16.to_le(),
            13_u16.to_le(),
            14_u16.to_le(),
        ];

        let dst: [u8; super::EXFAT_ENTRY_SIZE] = unsafe { core::mem::transmute(src) };
        assert_eq!(
            dst,
            [
                123, // typ
                234, // length
                0, 0, // name[0] in le
                1, 0, // name[1] in le
                2, 0, // name[2] in le
                3, 0, // name[3] in le
                4, 0, // name[4] in le
                5, 0, // name[5] in le
                6, 0, // name[6] in le
                7, 0, // name[7] in le
                8, 0, // name[8] in le
                9, 0, // name[9] in le
                10, 0, // name[10] in le
                11, 0, // name[11] in le
                12, 0, // name[12] in le
                13, 0, // name[13] in le
                14, 0, // name[14] in le
            ]
        );

        assert_ne!(
            format!("{:p}", core::ptr::addr_of!(src)),
            format!("{:p}", core::ptr::addr_of!(dst))
        );
    }

    #[test]
    fn test_struct_as_u8_slice() {
        let mut src = super::ExfatEntryLabel::new();
        assert_eq!(src.typ, 0);
        assert_eq!(src.length, 0);
        assert_eq!(src.name, [0; 15]);

        src.typ = 123;
        src.length = 234;
        src.name = [
            0_u16.to_le(),
            1_u16.to_le(),
            2_u16.to_le(),
            3_u16.to_le(),
            4_u16.to_le(),
            5_u16.to_le(),
            6_u16.to_le(),
            7_u16.to_le(),
            8_u16.to_le(),
            9_u16.to_le(),
            10_u16.to_le(),
            11_u16.to_le(),
            12_u16.to_le(),
            13_u16.to_le(),
            14_u16.to_le(),
        ];

        let dst = libfs::cast::as_u8_slice(&src);
        assert_eq!(
            dst,
            [
                123, // typ
                234, // length
                0, 0, // name[0] in le
                1, 0, // name[1] in le
                2, 0, // name[2] in le
                3, 0, // name[3] in le
                4, 0, // name[4] in le
                5, 0, // name[5] in le
                6, 0, // name[6] in le
                7, 0, // name[7] in le
                8, 0, // name[8] in le
                9, 0, // name[9] in le
                10, 0, // name[10] in le
                11, 0, // name[11] in le
                12, 0, // name[12] in le
                13, 0, // name[13] in le
                14, 0, // name[14] in le
            ]
        );

        assert_eq!(
            format!("{:p}", core::ptr::addr_of!(src)),
            format!("{:p}", core::ptr::from_ref(dst))
        );
    }

    #[test]
    fn test_struct_bytemuck_cast_ref() {
        let mut src = super::ExfatEntryLabel::new();
        assert_eq!(src.typ, 0);
        assert_eq!(src.length, 0);
        assert_eq!(src.name, [0; 15]);

        src.typ = 123;
        src.length = 234;
        src.name = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

        let dst: &super::ExfatEntryName = bytemuck::cast_ref(&src);
        assert_eq!(dst.typ, 123);
        assert_eq!(dst.unknown, 234);
        assert_eq!(dst.name, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

        assert_eq!(
            format!("{:p}", core::ptr::addr_of!(src)),
            format!("{:p}", core::ptr::from_ref(dst))
        );
    }

    #[test]
    fn test_struct_bytemuck_cast_mut() {
        let mut src = super::ExfatEntryLabel::new();
        let src_addr = format!("{:p}", core::ptr::addr_of!(src));
        assert_eq!(src.typ, 0);
        assert_eq!(src.length, 0);
        assert_eq!(src.name, [0; 15]);

        src.typ = 123;
        src.length = 234;
        src.name = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

        let dst: &mut super::ExfatEntryName = bytemuck::cast_mut(&mut src);
        let dst_addr = format!("{:p}", core::ptr::from_ref(dst));
        assert_eq!(dst.typ, 123);
        assert_eq!(dst.unknown, 234);
        assert_eq!(dst.name, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);

        dst.typ = 234;
        dst.unknown = 123;
        dst.name = [14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

        assert_eq!(src.typ, 234);
        assert_eq!(src.length, 123);
        assert_eq!(src.name, [14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);

        assert_eq!(src_addr, dst_addr);
    }
}
