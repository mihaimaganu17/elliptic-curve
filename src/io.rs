use core::array::TryFromSliceError;

/// Wrapper that reads over a stream of bytes
// This can be turned into a trait
pub struct Reader {
    cursor: usize,
    bytes: Vec<u8>,
}

impl Reader {
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self {
            cursor: 0,
            bytes,
        }
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Returns the amount of bytes not read from the cursor point up until the end of the buffer
    pub fn bytes_unread(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    /// Read the desired primitive `P` type from the underlying buffer. This function moves the
    /// cursor forward by the amount of bytes that were read
    pub fn read<P: PrimitiveRead, E: ReadEndian<P>>(&mut self) -> Result<P, ReaderError> {
        // Compute the bytes we need to read based on the size of the type
        let bytes_to_read = core::mem::size_of::<P>();
        // Read the bytes from the buffer
        let bytes = self.read_bytes(bytes_to_read)?;

        // Create the type from the given bytes
        Ok(E::from_bytes(bytes)?)
    }

    /// Peek the desired primitive `P` type from the underlying buffer. Unlike `read`, this
    /// function does not move the cursor forward.
    pub fn peek<P: PrimitiveRead, E: ReadEndian<P>>(&mut self) -> Result<P, ReaderError> {
        // Compute the bytes we need to read based on the size of the type
        let bytes_to_peek = core::mem::size_of::<P>();
        // Read the bytes from the buffer
        let bytes = self.peek_bytes(bytes_to_peek)?;

        // Create the type from the given bytes
        Ok(E::from_bytes(bytes)?)
    }

    /// Read `count` bytes from the buffer
    pub fn read_bytes(&mut self, count: usize) -> Result<&[u8], ReaderError> {
        // Read the number of requested bytes
        let bytes_read =
            self.bytes.get(self.cursor..(self.cursor + count)).ok_or(ReaderError::BufferTooSmall)?;
        // Update the cursor
        self.cursor += count;
        // Return the read bytes
        Ok(bytes_read)
    }

    /// Peek a number of `count` bytes from the underlying stream. This function does not move the
    /// stream cursor forward, unlike `read_bytes`
    pub fn peek_bytes(&self, count: usize) -> Result<&[u8], ReaderError> {
        let bytes_peeked =
            self.bytes.get(self.cursor..(self.cursor + count)).ok_or(ReaderError::BufferTooSmall)?;
        Ok(bytes_peeked)
    }
}

#[derive(Debug)]
pub enum ReaderError {
    BufferTooSmall,
    PrimitiveError(PrimitiveError),
}

impl From<PrimitiveError> for ReaderError {
    fn from(err: PrimitiveError) -> Self {
        Self::PrimitiveError(err)
    }
}

pub trait PrimitiveRead: Sized {
    fn from_bytes_le(bytes: &[u8]) -> Result<Self, PrimitiveError>;
    fn from_bytes_be(bytes: &[u8]) -> Result<Self, PrimitiveError>;
}

#[derive(Debug)]
pub enum PrimitiveError {
    NotEnoughBytes,
    TryFromSlice(TryFromSliceError),
}

impl From<TryFromSliceError> for PrimitiveError {
    fn from(err: TryFromSliceError) -> Self {
        Self::TryFromSlice(err)
    }
}

#[macro_export]
macro_rules! primitive_read {
    ($primitive:ty) => {
        impl $crate::io::PrimitiveRead for $primitive {
            fn from_bytes_le(bytes: &[u8]) -> Result<Self, PrimitiveError> {
                // Take the exact amount of bytes from the slice of the `bytes`
                let bytes = bytes
                    .get(0..core::mem::size_of::<$primitive>())
                    .ok_or(PrimitiveError::NotEnoughBytes)?;
                Ok(Self::from_le_bytes(bytes.try_into()?))
            }
            fn from_bytes_be(bytes: &[u8]) -> Result<Self, PrimitiveError> {
                // Take the exact amount of bytes from the slice of the `bytes`
                let bytes = bytes
                    .get(0..core::mem::size_of::<$primitive>())
                    .ok_or(PrimitiveError::NotEnoughBytes)?;
                Ok(Self::from_be_bytes(bytes.try_into()?))
            }
        }
    };
}

primitive_read!(u8);
primitive_read!(u16);
primitive_read!(u32);
primitive_read!(u64);
primitive_read!(u128);

pub trait ReadEndian<P: PrimitiveRead> {
    fn from_bytes(bytes: &[u8]) -> Result<P, PrimitiveError>;
}

pub struct LittleEndian;

impl<P: PrimitiveRead> ReadEndian<P> for LittleEndian {
    fn from_bytes(bytes: &[u8]) -> Result<P, PrimitiveError> {
        P::from_bytes_le(bytes)
    }
}

pub struct BigEndian;

impl<P: PrimitiveRead> ReadEndian<P> for BigEndian {
    fn from_bytes(bytes: &[u8]) -> Result<P, PrimitiveError> {
        P::from_bytes_be(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{Reader, BigEndian, LittleEndian};

    #[test]
    fn test_u32_be_read() {
        let bytes = std::fs::read("testdata/cafebabe.bin").unwrap();
        let mut reader = Reader::from_vec(bytes);
        let magic = reader.read::<u32, BigEndian>().expect("Failed to read u32 integer");

        assert!(magic == 0xcafebabe);
    }

    #[test]
    fn test_u32_le_read() {
        let bytes = std::fs::read("testdata/cafebabe.bin").unwrap();
        let mut reader = Reader::from_vec(bytes);
        let magic = reader.read::<u32, LittleEndian>().expect("Failed to read u32 integer");

        assert!(magic == 0xbebafeca);
    }

    #[test]
    fn test_u64_be_read() {
        let bytes = std::fs::read("testdata/cafebabeb00bcafe.bin").unwrap();
        let mut reader = Reader::from_vec(bytes);
        let magic = reader.read::<u64, BigEndian>().expect("Failed to read u32 integer");

        assert!(magic == 0xcafebabeb00bcafe);
    }

    #[test]
    fn test_u64_le_read() {
        let bytes = std::fs::read("testdata/cafebabeb00bcafe.bin").unwrap();
        let mut reader = Reader::from_vec(bytes);
        let magic = reader.read::<u64, LittleEndian>().expect("Failed to read u32 integer");

        assert!(magic == 0xfeca0bb0bebafeca);
    }

    #[test]
    fn test_peek_primitive() {
        let bytes = std::fs::read("testdata/cafebabeb00bcafe.bin").unwrap();
        let mut reader = Reader::from_vec(bytes);
        assert!(reader.cursor() == 0usize);

        let magic = reader.peek::<u64, LittleEndian>().expect("Failed to read u32 integer");
        assert!(magic == 0xfeca0bb0bebafeca);
        assert!(reader.cursor() == 0usize);
    }
}
