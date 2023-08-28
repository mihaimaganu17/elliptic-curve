/// Take a string slice as input in `src` and tries to decode it into a `Vec`
pub fn decode_hex(src: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..src.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&src[idx..idx+2], 16))
        .collect()
}
