use core::assert;
use alloc::vec::Vec;
use core::prelude::rust_2024::derive;
use core::default::Default;
use core::result::*;
use core::result::Result::*;
use bento::libc::*;

#[cfg(feature = "bitmap_u64")]
use byteorder::ByteOrder;

#[cfg(not(feature = "bitmap_u64"))]
pub type Block = u8;
#[cfg(feature = "bitmap_u64")]
pub type Block = u64;

pub const BLOCK_SIZE: usize = core::mem::size_of::<Block>();
pub const BLOCK_BITS: usize = BLOCK_SIZE * 8;

trait BlockTrait {
    fn is_min(&self) -> bool;
    fn is_max(&self) -> bool;
    fn minimize(&mut self);
    fn maximize(&mut self);
    fn set(&mut self, i: usize);
    fn clear(&mut self, i: usize);
    fn is_set(&self, i: usize) -> bool;
}

impl BlockTrait for Block {
    fn is_min(&self) -> bool {
        *self == Self::MIN
    }

    fn is_max(&self) -> bool {
        *self == Self::MAX
    }

    fn minimize(&mut self) {
        *self = Self::MIN;
    }

    fn maximize(&mut self) {
        *self = Self::MAX;
    }

    fn set(&mut self, i: usize) {
        *self |= 1 << i;
    }

    fn clear(&mut self, i: usize) {
        *self &= !(1 << i);
    }

    fn is_set(&self, i: usize) -> bool {
        (*self & (1 << i)) != 0
    }
}

#[derive(Default)]
pub struct Bitmap {
    block: Vec<Block>,
    #[cfg(feature = "bitmap_u64")]
    bytes: Vec<u8>,
}

impl Bitmap {
    /// # Errors
    pub fn new(num_bits: usize) -> Result<Self, i32> {
        Self::new_min(num_bits)
    }

    /// # Errors
    pub fn new_min(num_bits: usize) -> Result<Self, i32> {
        Self::new_impl(num_bits, Block::MIN)
    }

    /// # Errors
    pub fn new_max(num_bits: usize) -> Result<Self, i32> {
        Self::new_impl(num_bits, Block::MAX)
    }

    fn new_impl(num_bits: usize, value: Block) -> Result<Self, i32> {
        if num_bits % BLOCK_BITS != 0 {
            return Err(EINVAL);
        }
        Ok(Self {
            block: vec![value; num_bits.div_ceil(BLOCK_BITS)],
            #[cfg(feature = "bitmap_u64")]
            bytes: vec![],
        })
    }

    /// # Errors
    pub fn new_from_bytes(b: &[u8]) -> Result<Self, i32> {
        let mut bmp = Self::new(0)?;
        bmp.set_bytes(b)?;
        Ok(bmp)
    }

    #[must_use]
    pub fn as_block(&self) -> &[Block] {
        &self.block
    }

    #[cfg(not(feature = "bitmap_u64"))]
    #[must_use]
    pub fn as_bytes(&mut self) -> &[u8] {
        &self.block
    }

    #[cfg(feature = "bitmap_u64")]
    pub fn as_bytes(&mut self) -> &[u8] {
        if self.bytes.len() != self.get_size() / 8 {
            self.bytes = vec![0; self.get_size() / 8];
        }
        #[cfg(not(feature = "bitmap_be"))]
        byteorder::LittleEndian::write_u64_into(&self.block, &mut self.bytes);
        #[cfg(feature = "bitmap_be")]
        byteorder::BigEndian::write_u64_into(&self.block, &mut self.bytes);
        &self.bytes
    }

    #[cfg(not(feature = "bitmap_u64"))]
    /// # Errors
    pub fn set_bytes(&mut self, b: &[u8]) -> Result<(), i32> {
        self.block = b.to_vec();
        Ok(())
    }

    #[cfg(feature = "bitmap_u64")]
    /// # Errors
    pub fn set_bytes(&mut self, b: &[u8]) -> Result<(), i32> {
        if b.len() % BLOCK_SIZE != 0 {
            return Err(EINVAL);
        }
        if b.len() != self.get_size() / 8 {
            self.block = vec![Block::MIN; b.len() / BLOCK_SIZE];
        }
        #[cfg(not(feature = "bitmap_be"))]
        byteorder::LittleEndian::read_u64_into(b, &mut self.block);
        #[cfg(feature = "bitmap_be")]
        byteorder::BigEndian::read_u64_into(b, &mut self.block);
        Ok(())
    }

    #[must_use]
    pub fn get_size(&self) -> usize {
        self.block.len() * BLOCK_BITS
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.get_size() == 0
    }

    #[must_use]
    pub fn is_min(&self) -> bool {
        for b in &self.block {
            if !b.is_min() {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn is_max(&self) -> bool {
        for b in &self.block {
            if !b.is_max() {
                return false;
            }
        }
        true
    }

    pub fn minimize(&mut self) {
        for b in &mut self.block {
            b.minimize();
        }
    }

    pub fn maximize(&mut self) {
        for b in &mut self.block {
            b.maximize();
        }
    }

    /// # Errors
    pub fn set(&mut self, i: usize) -> Result<(), i32> {
        self.block
            .get_mut(i / BLOCK_BITS)
            .ok_or(EINVAL)?
            .set(i % BLOCK_BITS);
        Ok(())
    }

    /// # Errors
    pub fn clear(&mut self, i: usize) -> Result<(), i32> {
        self.block
            .get_mut(i / BLOCK_BITS)
            .ok_or(EINVAL)?
            .clear(i % BLOCK_BITS);
        Ok(())
    }

    /// # Errors
    pub fn is_set(&self, i: usize) -> Result<bool, i32> {
        Ok(self
            .block
            .get(i / BLOCK_BITS)
            .ok_or(EINVAL)?
            .is_set(i % BLOCK_BITS))
    }

    // end not inclusive
    fn get_block_index_range(beg: usize, end: usize) -> (usize, usize) {
        assert!(beg < end);
        (beg / BLOCK_BITS, end.div_ceil(BLOCK_BITS))
    }

    // end not inclusive
    fn get_block_bit_range(blk: usize, beg: usize, end: usize) -> (usize, usize) {
        assert!(beg < end);
        if beg / BLOCK_BITS == end / BLOCK_BITS {
            (
                core::cmp::max(0, beg % BLOCK_BITS),
                core::cmp::min(BLOCK_BITS, end % BLOCK_BITS),
            )
        } else if blk == beg / BLOCK_BITS {
            (core::cmp::max(0, beg % BLOCK_BITS), BLOCK_BITS)
        } else if blk == end / BLOCK_BITS {
            (0, core::cmp::min(BLOCK_BITS, end % BLOCK_BITS))
        } else {
            (0, BLOCK_BITS)
        }
    }

    /// # Errors
    pub fn set_from(&mut self) -> Result<usize, i32> {
        self.set_from_range(0, self.get_size())
    }

    /// # Errors
    pub fn set_from_range(&mut self, beg: usize, end: usize) -> Result<usize, i32> {
        let (beg_block, end_block) = Self::get_block_index_range(beg, end);
        for i in beg_block..end_block {
            let (beg_bit, end_bit) = Self::get_block_bit_range(i, beg, end);
            let b = self.block.get_mut(i).ok_or(EINVAL)?;
            if b.is_max() {
                continue;
            }
            for j in beg_bit..end_bit {
                if !b.is_set(j) {
                    b.set(j);
                    return Ok(BLOCK_BITS * i + j);
                }
            }
        }
        Ok(usize::MAX)
    }

    /// # Errors
    pub fn clear_from(&mut self) -> Result<usize, i32> {
        self.clear_from_range(0, self.get_size())
    }

    /// # Errors
    pub fn clear_from_range(&mut self, beg: usize, end: usize) -> Result<usize, i32> {
        let (beg_block, end_block) = Self::get_block_index_range(beg, end);
        for i in beg_block..end_block {
            let (beg_bit, end_bit) = Self::get_block_bit_range(i, beg, end);
            let b = self.block.get_mut(i).ok_or(EINVAL)?;
            if b.is_min() {
                continue;
            }
            for j in beg_bit..end_bit {
                if b.is_set(j) {
                    b.clear(j);
                    return Ok(BLOCK_BITS * i + j);
                }
            }
        }
        Ok(usize::MAX)
    }

    /// # Errors
    pub fn is_set_from(&self) -> Result<usize, i32> {
        self.is_set_from_range(0, self.get_size())
    }

    /// # Errors
    pub fn is_set_from_range(&self, beg: usize, end: usize) -> Result<usize, i32> {
        let (beg_block, end_block) = Self::get_block_index_range(beg, end);
        for i in beg_block..end_block {
            let (beg_bit, end_bit) = Self::get_block_bit_range(i, beg, end);
            let b = self.block.get(i).ok_or(EINVAL)?;
            for j in beg_bit..end_bit {
                if b.is_set(j) {
                    return Ok(BLOCK_BITS * i + j);
                }
            }
        }
        Ok(usize::MAX)
    }

    /// # Errors
    pub fn count_is_set_from(&self) -> Result<usize, i32> {
        self.count_is_set_from_range(0, self.get_size())
    }

    /// # Errors
    pub fn count_is_set_from_range(&self, beg: usize, end: usize) -> Result<usize, i32> {
        let (beg_block, end_block) = Self::get_block_index_range(beg, end);
        let mut total = 0;
        for i in beg_block..end_block {
            let (beg_bit, end_bit) = Self::get_block_bit_range(i, beg, end);
            let b = self.block.get(i).ok_or(EINVAL)?;
            if b.is_max() {
                total += BLOCK_BITS;
                continue;
            } else if b.is_min() {
                continue;
            }
            for j in beg_bit..end_bit {
                if b.is_set(j) {
                    total += 1;
                }
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    const N: usize = super::BLOCK_BITS;

    fn alloc(num_bits: usize) -> super::Bitmap {
        match super::Bitmap::new(num_bits) {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        }
    }

    fn alloc_max(num_bits: usize) -> super::Bitmap {
        match super::Bitmap::new_max(num_bits) {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn test_block() {
        assert_eq!(super::Block::MIN, 0);
    }

    #[test]
    fn test_bitmap_new() {
        assert!(super::Bitmap::new(0).is_ok());
        assert!(super::Bitmap::new(1).is_err());
        assert!(super::Bitmap::new(N).is_ok());
        assert!(super::Bitmap::new(N + 1).is_err());
        assert!(super::Bitmap::new(N * 2).is_ok());
        assert!(super::Bitmap::new(N * 2 + 1).is_err());
    }

    #[test]
    fn test_bitmap_new_from_bytes() {
        assert!(super::Bitmap::new_from_bytes(&[]).is_ok());
        #[cfg(feature = "bitmap_u64")]
        assert!(super::Bitmap::new_from_bytes(&[0]).is_err());
        assert!(super::Bitmap::new_from_bytes(&[0; N / 8]).is_ok());
        #[cfg(feature = "bitmap_u64")]
        assert!(super::Bitmap::new_from_bytes(&[0; N / 8 + 1]).is_err());
        assert!(super::Bitmap::new_from_bytes(&[0; N * 2 / 8]).is_ok());
        #[cfg(feature = "bitmap_u64")]
        assert!(super::Bitmap::new_from_bytes(&[0; N * 2 / 8 + 1]).is_err());
    }

    #[test]
    fn test_bitmap_as_block() {
        assert_eq!(alloc(0).as_block(), &[]);
        assert_eq!(alloc(N).as_block(), &[0; N / super::BLOCK_BITS]);
        assert_eq!(alloc(N * 2).as_block(), &[0; N * 2 / super::BLOCK_BITS]);

        assert_eq!(alloc_max(0).as_block(), &[]);
        assert_eq!(
            alloc_max(N).as_block(),
            &[super::Block::MAX; N / super::BLOCK_BITS]
        );
        assert_eq!(
            alloc_max(N * 2).as_block(),
            &[super::Block::MAX; N * 2 / super::BLOCK_BITS]
        );
    }

    #[test]
    fn test_bitmap_as_bytes() {
        assert_eq!(alloc(0).as_bytes(), &[]);
        assert_eq!(alloc(N).as_bytes(), &[0; N / 8]);
        assert_eq!(alloc(N * 2).as_bytes(), &[0; N * 2 / 8]);

        assert_eq!(alloc_max(0).as_bytes(), &[]);
        assert_eq!(alloc_max(N).as_bytes(), &[0xff; N / 8]);
        assert_eq!(alloc_max(N * 2).as_bytes(), &[0xff; N * 2 / 8]);
    }

    #[test]
    fn test_bitmap_set_bytes() {
        let mut bmp = alloc(0);
        assert!(bmp.set_bytes(&[0xff; N / 8]).is_ok());
        assert_eq!(bmp.as_block(), &[super::Block::MAX; N / super::BLOCK_BITS]);
        assert_eq!(bmp.as_bytes(), &[0xff; N / 8]);

        let mut bmp = alloc(N);
        assert!(bmp.set_bytes(&[0xff; N * 2 / 8]).is_ok());
        assert_eq!(
            bmp.as_block(),
            &[super::Block::MAX; N * 2 / super::BLOCK_BITS]
        );
        assert_eq!(bmp.as_bytes(), &[0xff; N * 2 / 8]);

        let mut bmp = alloc(N * 2);
        assert!(bmp.set_bytes(&[]).is_ok());
        assert_eq!(bmp.as_block(), &[]);
        assert_eq!(bmp.as_bytes(), &[]);
    }

    #[cfg(not(feature = "bitmap_u64"))]
    #[test]
    fn test_bitmap_endianness() {
        let mut bmp = match super::Bitmap::new_from_bytes(&[0x12, 0x34, 0x56, 0x78]) {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(bmp.as_block(), &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(bmp.as_bytes(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[cfg(feature = "bitmap_u64")]
    #[test]
    fn test_bitmap_endianness() {
        assert!(super::Bitmap::new_from_bytes(&[0x12, 0x34, 0x56, 0x78]).is_err());
        let mut bmp = match super::Bitmap::new_from_bytes(&[
            0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
        ]) {
            Ok(v) => v,
            Err(e) => panic!("{e}"),
        };
        #[cfg(not(feature = "bitmap_be"))]
        assert_eq!(bmp.as_block(), &[0x7856_3412_7856_3412]);
        #[cfg(feature = "bitmap_be")]
        assert_eq!(bmp.as_block(), &[0x1234_5678_1234_5678]);
        assert_eq!(
            bmp.as_bytes(),
            &[0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn test_bitmap_get_size() {
        assert!(alloc(0).block.is_empty());
        assert_eq!(alloc(N).get_size(), N);
        assert_eq!(alloc(N * 2).get_size(), N * 2);
    }

    #[test]
    fn test_bitmap_minimize() {
        let bmp1 = alloc(N * 2);
        let mut bmp2 = alloc_max(N * 2);
        assert_ne!(bmp1.block, bmp2.block);
        bmp2.minimize();
        assert_eq!(bmp1.block, bmp2.block);
        for x in 0..N * 2 {
            assert_eq!(bmp1.is_set(x), Ok(false));
            assert_eq!(bmp2.is_set(x), Ok(false));
        }
        assert!(bmp1.is_min());
        assert!(bmp2.is_min());
        assert!(!bmp1.is_max());
        assert!(!bmp2.is_max());
    }

    #[test]
    fn test_bitmap_maximize() {
        let mut bmp1 = alloc(N * 2);
        let bmp2 = alloc_max(N * 2);
        assert_ne!(bmp1.block, bmp2.block);
        bmp1.maximize();
        assert_eq!(bmp1.block, bmp2.block);
        for x in 0..N * 2 {
            assert_eq!(bmp1.is_set(x), Ok(true));
            assert_eq!(bmp2.is_set(x), Ok(true));
        }
        assert!(bmp1.is_max());
        assert!(bmp2.is_max());
        assert!(!bmp1.is_min());
        assert!(!bmp2.is_min());
    }

    #[test]
    fn test_bitmap_set() {
        let mut bmp = alloc(N * 2);
        assert_eq!(bmp.is_set(0), Ok(false));
        assert_eq!(bmp.set(0), Ok(()));
        assert_eq!(bmp.is_set(0), Ok(true));
        assert_eq!(bmp.is_set(N), Ok(false));
        assert_eq!(bmp.set(N), Ok(()));
        assert_eq!(bmp.is_set(N), Ok(true));
        assert!(bmp.is_set(N * 2).is_err());
        assert!(bmp.set(N * 2).is_err());
        assert!(bmp.is_set(N * 2).is_err());
    }

    #[test]
    fn test_bitmap_clear() {
        let mut bmp = alloc_max(N * 2);
        assert_eq!(bmp.is_set(0), Ok(true));
        assert_eq!(bmp.clear(0), Ok(()));
        assert_eq!(bmp.is_set(0), Ok(false));
        assert_eq!(bmp.is_set(N), Ok(true));
        assert_eq!(bmp.clear(N), Ok(()));
        assert_eq!(bmp.is_set(N), Ok(false));
        assert!(bmp.is_set(N * 2).is_err());
        assert!(bmp.clear(N * 2).is_err());
        assert!(bmp.is_set(N * 2).is_err());
    }

    #[test]
    fn test_bitmap_set_from_range() {
        let mut bmp = alloc(N * 2);
        for i in 0..N * 2 {
            assert_eq!(bmp.set_from_range(0, N * 2), Ok(i));
        }
        assert_eq!(bmp.set_from_range(0, N * 2), Ok(usize::MAX));
        assert_eq!(bmp.is_set_from_range(0, N * 2), Ok(0));
        assert!(bmp.set_from_range(0, N * 2 + 1).is_err());
        assert!(bmp.is_set_from_range(0, N * 2 + 1).is_ok());

        let mut bmp = alloc_max(N * 2);
        assert_eq!(bmp.set_from_range(0, N * 2), Ok(usize::MAX));
        assert_eq!(bmp.is_set_from_range(0, N * 2), Ok(0));
        assert!(bmp.set_from_range(0, N * 2 + 1).is_err());
        assert!(bmp.is_set_from_range(0, N * 2 + 1).is_ok());
    }

    #[test]
    fn test_bitmap_clear_from_range() {
        let mut bmp = alloc_max(N * 2);
        for i in 0..N * 2 {
            assert_eq!(bmp.clear_from_range(0, N * 2), Ok(i));
        }
        assert_eq!(bmp.clear_from_range(0, N * 2), Ok(usize::MAX));
        assert_eq!(bmp.is_set_from_range(0, N * 2), Ok(usize::MAX));
        assert!(bmp.clear_from_range(0, N * 2 + 1).is_err());
        assert!(bmp.is_set_from_range(0, N * 2 + 1).is_err());

        let mut bmp = alloc(N * 2);
        assert_eq!(bmp.clear_from_range(0, N * 2), Ok(usize::MAX));
        assert_eq!(bmp.is_set_from_range(0, N * 2), Ok(usize::MAX));
        assert!(bmp.clear_from_range(0, N * 2 + 1).is_err());
        assert!(bmp.is_set_from_range(0, N * 2 + 1).is_err());
    }

    #[test]
    fn test_bitmap_count_is_set_from_range() {
        let mut bmp = alloc(N * 2);
        assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(0));
        for i in 0..N * 2 {
            assert_eq!(bmp.set(i), Ok(()));
            assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(i + 1));
        }
        assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(N * 2));
        assert!(bmp.count_is_set_from_range(0, N * 2 + 1).is_err());

        let mut bmp = alloc_max(N * 2);
        assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(N * 2));
        for i in 0..N * 2 {
            assert_eq!(bmp.clear(i), Ok(()));
            assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(N * 2 - i - 1));
        }
        assert_eq!(bmp.count_is_set_from_range(0, N * 2), Ok(0));
        assert!(bmp.count_is_set_from_range(0, N * 2 + 1).is_err());
    }
}
