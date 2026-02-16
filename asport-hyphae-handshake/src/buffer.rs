//! Buffer trait used by Hyphae's handshake customization traits.
//! 

use std::ops::Range;

#[derive(Debug)]
pub struct BufferFullError;

/// Generic mutable byte buffer.
/// 
/// This is essentially a scoped down (but safe) version of `BufMut`
/// from the Bytes crate that has no dependency on `alloc`.
pub trait Buffer: AsMut<[u8]> + AsRef<[u8]> {
    fn remaining(&self) -> usize;

    fn len(&self) -> usize;

    fn push(&mut self, value: u8) -> Result<(), BufferFullError>;

    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), BufferFullError>;

    fn clear(&mut self);

    fn clear_range(&mut self, range: Range<usize>);
}

// Implement buffer for `Vec<u8>`.
#[cfg(any(test, feature = "alloc"))]
impl Buffer for Vec<u8> {
    fn remaining(&self) -> usize {
        usize::MAX - self.len()
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn push(&mut self, value: u8) -> Result<(), BufferFullError> {
        self.push(value);
        Ok(())
    }

    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), BufferFullError> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn clear(&mut self) {
        self.clear();
    }

    fn clear_range(&mut self, range: Range<usize>) {
        self.drain(range);
    }
}

/// `AppendOnlyBuffer` wraps any `&mut Buffer` with one that can extend
/// the inner buffer, but cannot access or clear its existing contents.
pub(crate) struct AppendOnlyBuffer<'a, T: Buffer> {
    inner: &'a mut T,
    suffix_start: usize,
}

impl <'a, T: Buffer> AppendOnlyBuffer<'a, T> {
    pub fn new(inner: &'a mut T) -> Self {
        Self {
            suffix_start: inner.len(),
            inner,
        }
    }
}

impl <T: Buffer> Buffer for AppendOnlyBuffer<'_, T> {
    fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    fn len(&self) -> usize {
        self.inner.len() - self.suffix_start
    }

    fn push(&mut self, value: u8) -> Result<(), BufferFullError> {
        self.inner.push(value)
    }

    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), BufferFullError> {
        self.inner.extend_from_slice(slice)
    }

    fn clear(&mut self) {
        self.inner.clear_range(self.suffix_start..self.inner.len());
    }

    fn clear_range(&mut self, range: Range<usize>) {
        self.inner.clear_range(range.start + self.suffix_start..range.end + self.suffix_start);
    }
}

impl <T: Buffer> AsRef<[u8]> for AppendOnlyBuffer<'_, T> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.as_ref()[self.suffix_start..]
    }
}

impl <T: Buffer> AsMut<[u8]> for AppendOnlyBuffer<'_, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[self.suffix_start..]
    }
}

/// `MaxLenBuffer` wraps any `&mut Buffer` with one that cannot be
/// extended beyond the specified maximum length.
pub(crate) struct MaxLenBuffer<'a, T: Buffer> {
    inner: &'a mut T,
    max_len: usize,
}

impl <'a, T: Buffer> MaxLenBuffer<'a, T> {
    pub fn new(inner: &'a mut T, max_len: usize) -> Result<Self, BufferFullError> {
        if inner.len() <= max_len {
            Ok(Self {
                inner,
                max_len
            })
        } else {
            Err(BufferFullError)
        }
    }
}

impl <T: Buffer> Buffer for MaxLenBuffer<'_, T> {
    fn remaining(&self) -> usize {
        self.inner
            .remaining()
            .min(self.max_len - self.len())
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn push(&mut self, value: u8) -> Result<(), BufferFullError> {
        if self.remaining() > 0 {
            self.inner.push(value)
        } else {
            Err(BufferFullError)
        }
    }

    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), BufferFullError> {
        if slice.len() <= self.remaining() {
            self.inner.extend_from_slice(slice)
        } else {
            Err(BufferFullError)
        }
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn clear_range(&mut self, range: Range<usize>) {
        self.inner.clear_range(range);
    }
}

impl <T: Buffer> AsRef<[u8]> for MaxLenBuffer<'_, T> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl <T: Buffer> AsMut<[u8]> for MaxLenBuffer<'_, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.inner.as_mut()
    }
}

/// Wraps any `&mut Buffer` with a `VarLengthPrefixBuffer` which
/// automatically writes a `VarInt` length prefix in front of it's data.
pub(crate) struct VarLengthPrefixBuffer<'a, T: Buffer> {
    inner: AppendOnlyBuffer<'a, T>,
}

impl <'a, T: Buffer> VarLengthPrefixBuffer<'a, T> {
    pub fn new(inner: &'a mut T, expect_len: usize) -> Result<Self, BufferFullError> {
        let mut this = Self {
            inner: AppendOnlyBuffer::new(inner),
        };
        this.inner.push(0)?;
        this.reserve_prefix_for_buffer(expect_len)?;
        Ok(this)
    }

    fn reserve_prefix_for_buffer(&mut self, buffer_len: usize) -> Result<(), BufferFullError> {
        let min_prefix_size = VarIntSize::from_value(buffer_len as u64).ok_or(BufferFullError)?;
        let cur_prefix_size = self.get_prefix_size();
        if min_prefix_size > cur_prefix_size {
            let pad_by = min_prefix_size.len() - cur_prefix_size.len();
            let orig_inner_len = self.inner.len();
            if self.inner.remaining() < pad_by {
                return Err(BufferFullError);
            }
            for _ in 0..pad_by {
                self.inner.push(0).unwrap(); // Already checked remaining.
            }
            self.inner.as_mut().copy_within(cur_prefix_size.len()..orig_inner_len, min_prefix_size.len());
        }
        self.inner.as_mut()[0] = min_prefix_size.msb();
        Ok(())
    }

    fn finalize_prefix(&mut self) {
        let prefix_len = self.get_prefix_size().len();
        VarIntSize::write_varint(self.len() as u64, &mut self.inner.as_mut()[0..prefix_len]);
    }

    fn get_prefix_size(&self) -> VarIntSize {
        VarIntSize::from_msb(self.inner.as_ref()[0])
    }
}

impl <T: Buffer> Drop for VarLengthPrefixBuffer<'_, T> {
    fn drop(&mut self) {
        if self.inner.len() > 0 {
            self.finalize_prefix();
        }
    }
}

impl <T: Buffer> Buffer for VarLengthPrefixBuffer<'_, T> {
    fn remaining(&self) -> usize {
        // TODO, this is the worst case, fix me
        self.inner.remaining().checked_sub(7).unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.inner.len() - self.get_prefix_size().len()
    }

    fn push(&mut self, value: u8) -> Result<(), BufferFullError> {
        self.reserve_prefix_for_buffer(self.len() + 1)?;
        self.inner.push(value)
    }

    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), BufferFullError> {
        self.reserve_prefix_for_buffer(self.len() + slice.len())?;
        self.inner.extend_from_slice(slice)
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.push(0).unwrap(); // Buffer already had space for this.
    }

    fn clear_range(&mut self, range: Range<usize>) {
        let prefix_len = self.get_prefix_size().len();
        self.inner.clear_range(range.start + prefix_len..range.end + prefix_len);
    }
}

impl <T: Buffer> AsRef<[u8]> for VarLengthPrefixBuffer<'_, T> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.as_ref()[self.get_prefix_size().len()..]
    }
}

impl <T: Buffer> AsMut<[u8]> for VarLengthPrefixBuffer<'_, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        let start = self.get_prefix_size().len();
        &mut self.inner.as_mut()[start..]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum VarIntSize {
    VarInt1,
    VarInt2,
    VarInt4,
    VarInt8,
}

impl VarIntSize {
    pub const fn len(self) -> usize {
        match self {
            Self::VarInt1 => 1,
            Self::VarInt2 => 2,
            Self::VarInt4 => 4,
            Self::VarInt8 => 8,
        }
    }

    pub const fn from_len(len: usize) -> Option<Self> {
        match len {
            1 => Some(Self::VarInt1),
            2 => Some(Self::VarInt2),
            4 => Some(Self::VarInt4),
            8 => Some(Self::VarInt8),
            _ => None,
        }
    }

    pub const fn max_value(self) -> u64 {
        2u64.pow(self.len() as u32 * 8 - 2) - 1
    }

    pub const fn msb(self) -> u8 {
        match self {
            Self::VarInt1 => 0x00,
            Self::VarInt2 => 0x40,
            Self::VarInt4 => 0x80,
            Self::VarInt8 => 0xC0,
        }
    }

    pub const fn from_msb(msb: u8) -> Self {
        match msb & Self::VarInt8.msb() {
            0x00 => Self::VarInt1,
            0x40 => Self::VarInt2,
            0x80 => Self::VarInt4,
            0xC0 => Self::VarInt8,
            _ => unreachable!(),
        }
    }

    pub const fn from_value(value: u64) -> Option<Self> {
        match value {
            v if v <= Self::VarInt1.max_value() => Some(Self::VarInt1),
            v if v <= Self::VarInt2.max_value() => Some(Self::VarInt2),
            v if v <= Self::VarInt4.max_value() => Some(Self::VarInt4),
            v if v <= Self::VarInt8.max_value() => Some(Self::VarInt8),
            _ => None,
        }
    }

    /// Write `value` in `QUIC VarInt` encoding into `buffer`.
    /// 
    /// Panics if buffer is not 1, 2, 4, or 8 bytes or if `value` cannot
    /// fit in a `VarInt` of `buffer.len()`.
    pub fn write_varint(value: u64, buffer: &mut [u8]) {
        let buffer_size = Self::from_len(buffer.len()).expect("valid buffer len");
        let min_buffer_size = Self::from_value(value).expect("valid varint value");
        if buffer_size < min_buffer_size {
            panic!("buffer too small to hold value");
        }
        match buffer_size {
            VarIntSize::VarInt1 => buffer.copy_from_slice((value as u8).to_be_bytes().as_slice()),
            VarIntSize::VarInt2 => buffer.copy_from_slice((value as u16).to_be_bytes().as_slice()),
            VarIntSize::VarInt4 => buffer.copy_from_slice((value as u32).to_be_bytes().as_slice()),
            VarIntSize::VarInt8 => buffer.copy_from_slice((value as u64).to_be_bytes().as_slice()),
        }
        buffer[0] |= buffer_size.msb();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varlen_prefix_buffer() {
        let mut buffer = Vec::new();
        let varlen_prefix_buffer = VarLengthPrefixBuffer::new(&mut buffer, 0).unwrap();
        drop(varlen_prefix_buffer);
        assert_eq!(&buffer, &[0x00]);

        let mut buffer = Vec::new();
        let varlen_prefix_buffer = VarLengthPrefixBuffer::new(&mut buffer, 10000).unwrap();
        drop(varlen_prefix_buffer);
        assert_eq!(&buffer, &[0x40, 0x00]);

        let mut buffer = Vec::new();
        let mut varlen_prefix_buffer = VarLengthPrefixBuffer::new(&mut buffer, 0).unwrap();
        varlen_prefix_buffer.extend_from_slice(&[1;64]).unwrap();
        drop(varlen_prefix_buffer);
        assert_eq!(buffer.len(), 66);
        assert_eq!(&buffer[0..2], &[0x40, 64]);
        assert_eq!(&buffer[2..], &[1; 64]);

        let mut buffer = Vec::new();
        let mut varlen_prefix_buffer = VarLengthPrefixBuffer::new(&mut buffer, 0).unwrap();
        varlen_prefix_buffer.extend_from_slice(&[1;64]).unwrap();
        varlen_prefix_buffer.clear_range(16..48);
        drop(varlen_prefix_buffer);
        assert_eq!(buffer.len(), 34);
        assert_eq!(&buffer[0..2], &[0x40, 32]);
        assert_eq!(&buffer[2..], &[1; 32]);
    }
}
