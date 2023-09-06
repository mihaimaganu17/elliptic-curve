use crate::io::{Reader, ReaderError, LittleEndian};

/// Take a string slice as input in `src` and tries to decode it into a `Vec`
pub fn decode_hex(src: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..src.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&src[idx..idx+2], 16))
        .collect()
}

// The first boundary is if the number if smaller than 253, which is 0xfd in hex
const VARIANT_1BYTE_BOUNDARY: u64 = 0xFD;
// The next boundary, for 2 bytes encoding is 2^16 - 1
const VARIANT_2BYTE_BOUNDARY: u64 = 0xFFFF;
// The next boundary, for 4 bytes encoding is 2^32 - 1
const VARIANT_4BYTE_BOUNDARY: u64 = 0xFFFF_FFFF;
// The last boundary, for 8 bytes encoding is 2^64 - 1
const VARIANT_8BYTE_BOUNDARY: u64 = u64::MAX;

// Marks that the Variant is encoded as a 2-bytes integer
const VARIANT_2BYTE_MARKER: u8 = 0xfd;
// Marks that the Variant is encoded as a 4-bytes integer
const VARIANT_4BYTE_MARKER: u8 = 0xfe;
// Marks that the Variant is encoded as a 2-bytes integer
const VARIANT_8BYTE_MARKER: u8 = 0xff;

/// Variant integers or how to encode and serialize integers with less bytes than needed
#[derive(PartialEq, Eq, Debug)]
pub struct Variant(u64);

impl From<u64> for Variant {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Variant {
    /// Create a new `Variant`
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Encodes an integer as a variant
    pub fn encode(&self) -> Vec<u8> {
        // We can have at most 8-bytes representation for an `u64` + 1-byte that identifies the
        // encoding
        let mut bytes = Vec::with_capacity(9);

        // If the number is < 253, we just encode it in one byte
        if self.0 < VARIANT_1BYTE_BOUNDARY {
            let le_bytes = self.0.to_le_bytes();
            bytes.push(le_bytes[0]);
        // If the number is between 253 and 2^16 - 1
        } else if self.0 <= VARIANT_2BYTE_BOUNDARY {
            let le_bytes = self.0.to_le_bytes();
            bytes.push(VARIANT_2BYTE_MARKER);
            bytes.push(le_bytes[0]);
            bytes.push(le_bytes[1]);
        // If the number is between 2^16 and 2^32 - 1
        } else if self.0 <= VARIANT_4BYTE_BOUNDARY {
            let le_bytes = self.0.to_le_bytes();
            bytes.push(VARIANT_4BYTE_MARKER);
            bytes.push(le_bytes[0]);
            bytes.push(le_bytes[1]);
            bytes.push(le_bytes[2]);
            bytes.push(le_bytes[3]);
        // If the number is between 2^16 and 2^32 - 1
        } else if self.0 <= VARIANT_8BYTE_BOUNDARY {
            let le_bytes = self.0.to_le_bytes();
            bytes.push(VARIANT_8BYTE_MARKER);
            bytes.extend_from_slice(&le_bytes);
        }

        bytes
    }

    /// Parse a `Variant` integer from a reader
    pub fn parse(reader: &mut Reader) -> Result<Self, VariantError> {
        // Read the first byte
        let marker = reader.read::<u8, LittleEndian>()?;

        // Based on the marker, we will know what we have to read
        let value = match marker {
            VARIANT_2BYTE_MARKER => reader.read::<u16, LittleEndian>()? as u64,
            VARIANT_4BYTE_MARKER => reader.read::<u32, LittleEndian>()? as u64,
            VARIANT_8BYTE_MARKER => reader.read::<u64, LittleEndian>()? as u64,
            _ => marker as u64,
        };

        Ok(Variant::from(value))
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
pub enum VariantError {
    Reader(ReaderError),
}

impl From<ReaderError> for VariantError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
    }
}

#[cfg(test)]
mod tests {
    use super::Variant;
    use crate::io::Reader;

    #[test]
    fn test_variant_encoding() {
        let test_pairs = [
            (100, vec![0x64]),
            (255, vec![0xfd, 0xff, 0x00]),
            (555, vec![0xfd, 0x2b, 0x02]),
            (70015, vec![0xfe, 0x7f, 0x11, 0x01, 0x00]),
            (18005558675309, vec![0xff, 0x6d, 0xc7, 0xed, 0x3e, 0x60, 0x10, 0x00, 0x00]),
        ];

        for (input, output) in test_pairs {
            let variant = Variant::from(input);
            let bytes = variant.encode();
            assert_eq!(bytes, output);
        }
    }

    #[test]
    fn test_variant_parsing() {
        let test_pairs = [
            (100, vec![0x64]),
            (255, vec![0xfd, 0xff, 0x00]),
            (555, vec![0xfd, 0x2b, 0x02]),
            (70015, vec![0xfe, 0x7f, 0x11, 0x01, 0x00]),
            (18005558675309, vec![0xff, 0x6d, 0xc7, 0xed, 0x3e, 0x60, 0x10, 0x00, 0x00]),
        ];

        for (output, input) in test_pairs {
            let mut reader = Reader::from_vec(input);
            let parsed_variant =
                Variant::parse(&mut reader).expect("Failed to parse variant value");
            let variant = Variant::from(output);
            assert_eq!(parsed_variant, variant);
        }
    }
}
