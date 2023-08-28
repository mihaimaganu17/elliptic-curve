use primitive_types::U256;
use sha2::Digest;
use sha2::Sha256;

/// Compute the sha 256 hash value twice for the `bytes` and return it as a `U256` Big Endian
pub fn double_sha256(bytes: &[u8]) -> U256 {
    let mut hasher = Sha256::new();
    hasher.update(bytes);

    let result = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(result);

    let result = hasher.finalize();

    U256::from_big_endian(result.as_slice())
}
