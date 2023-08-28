use crate::curve::{pow_mod, Secp256K1Point, Secp256K1PointError};
use crate::serialise::{encode_der_value, EncodingError, DER_ENCODING_MARKER, DER_MAX_LEN};
use finite_field::Element;
use hmac::{Hmac, Mac};
use primitive_types::U256;
use sha2::Sha256;

#[derive(Debug)]
pub struct Signature {
    // This represents the the target we are aiming for
    r: U256,
    s: U256,
}

impl Signature {
    /// Creates a new `Signature` given an `r` and an `s`
    pub fn new(r: U256, s: U256) -> Self {
        Self { r, s }
    }

    /// Encodes the signature in a DER(Distinguished Encoding Rules) format
    pub fn der(self) -> Result<Vec<u8>, EncodingError> {
        // Instantiate a new `Vec` which will hold the DER encoding
        let mut der_encoding = Vec::with_capacity(DER_MAX_LEN);
        // Add the marker for the DER encoding
        der_encoding.push(DER_ENCODING_MARKER);

        // Encode the value for `r`
        let r_encoding = encode_der_value(self.r)?;
        // Encode the value for `s`
        let s_encoding = encode_der_value(self.s)?;

        // Compute the size for the rest of the encoding, excluding the marker
        let remaining_enc_size = r_encoding.len() + s_encoding.len();
        // Push the rest of the encoding size
        der_encoding.push(remaining_enc_size as u8);

        // Add the encoding for `r`
        der_encoding.extend(r_encoding);
        // Add the encoding for `s`
        der_encoding.extend(s_encoding);

        Ok(der_encoding)
    }

    pub fn r(&self) -> U256 {
        self.r
    }
    pub fn s(&self) -> U256 {
        self.s
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PrivateKey {
    secret: U256,
    point: Secp256K1Point,
    generator: Secp256K1Point,
}

#[derive(Debug)]
pub enum PrivateKeyError {
    Secp256K1PointError(Secp256K1PointError),
    InvalidX,
}

impl From<Secp256K1PointError> for PrivateKeyError {
    fn from(err: Secp256K1PointError) -> Self {
        Self::Secp256K1PointError(err)
    }
}

impl PrivateKey {
    pub fn new(secret: U256) -> Result<Self, Secp256K1PointError> {
        let generator = Secp256K1Point::generator()?;
        let point = (generator * secret)?;
        Ok(Self {
            secret,
            point,
            generator,
        })
    }

    pub fn point(&self) -> Secp256K1Point {
        self.point
    }

    pub fn sign(&self, z: U256) -> Result<Signature, PrivateKeyError> {
        let k = self.deterministic_k(z);
        // Compute the x-coordinate of R, which is k*G
        let r = (self.generator * k)?
            .point()
            .x()
            .ok_or(PrivateKeyError::InvalidX)?
            .value;

        // Compute the inverse of k
        let k_inv = pow_mod(
            k,
            self.generator.order() - U256::from(2u8),
            self.generator.order(),
        );
        // Compute s=(z+r*e)/k
        let s = (z + r.mul_mod(self.secret, self.generator.order()))
            .mul_mod(k_inv, self.generator.order());

        // Return the signature
        Ok(Signature::new(r, s))
    }

    fn deterministic_k(&self, z: U256) -> U256 {
        // Sequence of bytes filled with zero
        let k = [0; 32];
        // Sequence of bytes filled with one
        let v = [1; 32];

        let order = self.point.order();

        // --------------------------- Part 1 --------------------------------
        // Create a new `Vec` that can store (v, 0x00, secret, z) where
        // v, secret and z are all 256-bit or 32-byte unsigned integers
        let mut hmac_msg_slice: Vec<u8> = Vec::with_capacity(32 * 3 + 1);
        // Since the `Vec` is only instantiated, the len is currently 0. So resizing it as we do
        // below will only fill the structure with zeros
        hmac_msg_slice.resize(32 * 3 + 1, 0);

        hmac_msg_slice.get_mut(0..32).unwrap().copy_from_slice(&v);
        hmac_msg_slice[32] = 0;
        self.secret.to_big_endian(&mut hmac_msg_slice[33..65]);
        z.to_big_endian(&mut hmac_msg_slice[65..97]);

        let mut k_hash = compute_hmac_sha256(&k, &hmac_msg_slice);
        let mut v_hash = compute_hmac_sha256(&k_hash, &v);

        // --------------------------- Part 2 --------------------------------
        hmac_msg_slice.fill(0);
        hmac_msg_slice
            .get_mut(0..32)
            .unwrap()
            .copy_from_slice(&v_hash);
        hmac_msg_slice[32] = 1;
        self.secret.to_big_endian(&mut hmac_msg_slice[33..65]);
        z.to_big_endian(&mut hmac_msg_slice[65..97]);

        k_hash = compute_hmac_sha256(&k_hash, &hmac_msg_slice);
        v_hash = compute_hmac_sha256(&k_hash, &v_hash);

        loop {
            v_hash = compute_hmac_sha256(&k_hash, &v_hash);

            let candidate = U256::from_big_endian(&v_hash);
            if candidate >= U256::one() && candidate < order {
                return candidate;
            }

            let mut msg_slice: Vec<u8> = Vec::with_capacity(32 + 1);
            msg_slice.extend_from_slice(&v_hash);
            msg_slice.push(0);

            k_hash = compute_hmac_sha256(&k_hash, &msg_slice);
            v_hash = compute_hmac_sha256(&k_hash, &v_hash);
        }
    }
}

// Compute the Sh256 encoded Hmac for the given `key` and `data`
fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // Instantiate a new MAC (message authentication code) with the given `key` over `sha256`
    // algorithm
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can swallow any key");
    // Update the `mac` with the given key
    mac.update(data);
    // Construct the result
    let result = mac.finalize();
    // Return the resulted Hmac
    result.into_bytes().to_vec()
}
