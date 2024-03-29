use primitive_types::{U256, U512};
use uint::FromStrRadixErr;
use crate::hashing::double_sha256;

// Maximum DER encoding length, which is comprised of:
// - 1 byte for 0x30 Marker
// - 1 byte for length of the encoded signature (usually 0x44 or 0x45)
// - 1 byte for the marker of `r` value (0x02)
// - 1 byte for the `r` value length
// - at most 33 bytes (includin 0x00 prepended byte for `r`), can be less since this value
// has all the prepending zeros (except for the marker one) removed
// - 1 byte for the marker of `s` value (0x02)
// - 1 byte for the `s` value length
// - at most 33 bytes (includin 0x00 prepended byte for `s`), can be less since this value
// has all the prepending zeros (except for the marker one) removed
pub const DER_MAX_LEN: usize = 4 * 1 + 33 + 2 * 1 + 33;

// Marker for the DER encoding, similar to a format magic
pub const DER_ENCODING_MARKER: u8 = 0x30;

// Marker for a value inside the DER encoding
const DER_VALUE_MARKER: u8 = 0x02;

// Takes a `U256` and encodes it as a DER format value
pub fn encode_der_value(value: U256) -> Result<Vec<u8>, EncodingError> {
    // instatiate an `array` we can use as buffer to store `value`'s bytes
    let mut value_buffer = [0; 32];
    // convert `value` into bytes and write them to the buffer
    value.to_big_endian(&mut value_buffer);
    // strip all leading zeros
    let mut value_bytes = value_buffer
        .into_iter()
        .skip_while(|&x| x == 0)
        .collect::<Vec<u8>>();

    // Allocate a new `Vec` to hold the encoding of the `value`
    // - We need space for 2 Markers, each 1 byte in size
    // - And at most 33 bytes including the prepended `0x00` byte
    let mut value_encoding = Vec::with_capacity(2 + 33);

    // Push the `Marker` for the `value`
    value_encoding.push(DER_VALUE_MARKER);
    // Check if `value` has the high bit set
    if *value_bytes.get(0).ok_or(EncodingError::ZeroLengthValue)? & 0x80 != 0 {
        // If it has the high bit set, we prepend it with a zero byte
        value_bytes.insert(0, 0u8);
    }
    // Now we push the lenght of `value`. Since we know that the length can be at most 33, it is
    // safe to cast it as an `u8`
    value_encoding.push(value_bytes.len() as u8);
    // And finaly we add the bytes of `value`
    value_encoding.extend(value_bytes);

    Ok(value_encoding)
}

// The Base58 alfhabet is made up of all the alpha-numerical characters, except for the following
// pairs:
// - 0(zero) and O (bit o)
// - l(lowercase L) and I(uppercase i)
const _BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Take a `U256` value and convert it to Base58
pub fn _encode_base58(buffer: &[u8]) -> Result<String, EncodingError> {
    // Count all the leading zeros
    let leading_zeros = buffer.iter().take_while(|&x| *x == 0).count();

    // Costruct a prefix of `1` (ones) which is the Base58 character for zero
    let prefix = std::iter::repeat('1')
        .take(leading_zeros)
        .collect::<String>();

    // Instantiate an empty string to store th result
    let mut encoding = String::from("");

    // Encode the given value in an U512 value
    // This is in order to cover the WIF as well
    let mut value = U512::from_big_endian(buffer);

    // While our value is not zero
    while value > U512::zero() {
        // Compute the remainder of the operation
        let remainder: usize = (value % _BASE58_ALPHABET.len()).as_usize();
        // Get the mapped value from the Base58 alphabet. Since we cannot inter string slices
        // because they are made up of UTF-8 characters, we need to do this
        let base58_char = _BASE58_ALPHABET
            .chars()
            .nth(remainder)
            .ok_or(EncodingError::OutOfRange)?;
        // Insert it to the beginning of the string
        encoding.insert(0, base58_char);
        // Reduce the initial value
        value = value / _BASE58_ALPHABET.len();
    }

    // We also insert the prefix and return the value
    encoding.insert_str(0, &prefix);

    // Return the resulting encoding
    Ok(encoding)
}

pub fn encode_base58_checksum(buffer: &[u8]) -> Result<String, EncodingError> {
    // Compute the double `Sha256` for the given buffer
    let double_sha256 = double_sha256(buffer);

    // We need to concatenate the first 4 bytes of the double sha256 result with the buffer. So we
    // convert it to a `String` in order to do that
    let mut buffer = buffer.to_vec();

    // Take the first 4 bytes from the double sha256 result
    for idx in 0..4 {
        // Convert each byte into a `char`
        let new_byte = double_sha256[idx];
        // Push the `char` in the buffer
        buffer.push(new_byte);
    }

    _encode_base58(&buffer)
}

/// Issues an error whenever encoding goes wrong
#[derive(Debug)]
pub enum EncodingError {
    ZeroLengthValue,
    OutOfRange,
    FromStrRadixErr(FromStrRadixErr),
}

impl From<FromStrRadixErr> for EncodingError {
    fn from(err: FromStrRadixErr) -> Self {
        Self::FromStrRadixErr(err)
    }
}

