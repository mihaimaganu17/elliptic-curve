use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

/// Compute the sha 256 hash value twice for the `bytes` and return it as a `U256` Big Endian
pub fn double_sha256(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);

    let result = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(result);

    let result = hasher.finalize();

    result.to_vec()
}

/// Compute a Sha256 digest followed by a Ripemd160 digest on the given data and return the result
pub fn hash160(bytes: &[u8]) -> Vec<u8> {
    // ----------------------------- Compute the sha256 digest ------------------------------------

    // Create a new hasher
    let mut sha256_hasher = Sha256::new();
    // Add the messages bytes
    sha256_hasher.update(bytes);
    // Finalize and get the result
    let result = sha256_hasher.finalize();

    // ----------------------------- Compute the rpemd160 digest ----------------------------------

    // Create a new hasher
    let mut ripemd160_hasher = Ripemd160::new();
    // Feed the bytes in
    ripemd160_hasher.update(result.as_slice());
    // Finalize and get the result
    let result = ripemd160_hasher.finalize();

    result.to_vec()
}
