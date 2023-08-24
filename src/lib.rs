use core::fmt::Debug;
use core::ops::{Add, Div, Mul, Sub};
use finite_field::{Element, FieldElement, FieldElementError};
use hmac::{Hmac, Mac};
use primitive_types::U256;
use sha2::{Digest, Sha256};

/// Represents a point on an elliptic curve.
/// We could make the curse a generic parameter?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Point<P: PointElement> {
    a: P,
    b: P,
    x: Option<P>,
    y: Option<P>,
}

pub trait PointElement:
    Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Div<Output = Self>
    + Sized
    + PartialEq
    + Clone
    + Copy
    + Debug
{
    fn pow(self, exponent: u32) -> Self;
    fn mul_i64(&self, other: i64) -> Self;
    fn as_i64(&self) -> i64;
    fn is_zero(&self) -> bool;
    fn is_one(&self) -> bool;
    fn sqrt(&self) -> Self;
}

impl PointElement for i64 {
    fn pow(self, exponent: u32) -> Self {
        self.pow(exponent)
    }

    fn mul_i64(&self, other: i64) -> Self {
        *self * other
    }

    fn as_i64(&self) -> i64 {
        *self
    }
    fn is_zero(&self) -> bool {
        *self == 0i64
    }
    fn is_one(&self) -> bool {
        *self == 1i64
    }
    fn sqrt(&self) -> Self {
        *self
    }
}

impl PointElement for FieldElement<i64> {
    fn pow(self, exponent: u32) -> Self {
        self.pow(exponent.into()).unwrap()
    }

    fn mul_i64(&self, other: i64) -> Self {
        let value = self.value.mul_mod(other, self.order);
        Self {
            value,
            order: self.order,
        }
    }

    fn as_i64(&self) -> i64 {
        self.value
    }

    fn is_zero(&self) -> bool {
        self.value == 0i64
    }
    fn is_one(&self) -> bool {
        self.value == 1i64
    }
    fn sqrt(&self) -> Self {
        *self
    }
}

impl PointElement for FieldElement<U256> {
    fn pow(self, exponent: u32) -> Self {
        self.pow(U256::from(exponent)).unwrap()
    }

    fn mul_i64(&self, other: i64) -> Self {
        let value = self.value.mul_mod(U256::from(other), self.order);
        Self {
            value,
            order: self.order,
        }
    }

    fn as_i64(&self) -> i64 {
        self.value.low_u64() as i64
    }

    fn is_zero(&self) -> bool {
        self.value == U256::zero()
    }
    fn is_one(&self) -> bool {
        self.value == U256::zero()
    }

    fn sqrt(&self) -> Self {
        self.pow((self.order + U256::from(1)) / U256::from(4))
            .unwrap()
    }
}

impl<P: PointElement> Point<P> {
    /// Created a new `Point`
    pub fn new(a: P, b: P, x: Option<P>, y: Option<P>) -> Result<Self, PointError<P>> {
        // This represents that the point is the identity point and we just return it, without
        // checking it's presence on the curve
        if x.is_none() && y.is_none() {
            return Ok(Self {
                a,
                b,
                x: None,
                y: None,
            });
        }

        // At this point it is safe to unwrap
        let (x1, y1) = (x.unwrap(), y.unwrap());

        // of this small library
        if y1.pow(2) != x1.pow(3) + a * x1 + b {
            return Err(PointError::NotOnCurve(a, b, x1, y1));
        }

        Ok(Self {
            a,
            b,
            x: Some(x1),
            y: Some(y1),
        })
    }
}

impl<P: PointElement> Add for Point<P> {
    type Output = Result<Self, PointError<P>>;

    fn add(self, other: Self) -> Self::Output {
        // Check if the 2 points are on the same curve
        if self.a != other.a || self.b != other.b {
            return Err(PointError::DifferentCurves(
                self.a, self.b, other.a, other.b,
            ));
        }

        // If `self` is point at infinity, we return the `other` element
        if self.x.is_none() && self.y.is_none() {
            return Ok(other);
        }
        // If `other` is point at infinity, we return the `self` element
        if other.x.is_none() && other.y.is_none() {
            return Ok(self);
        }

        // At this point, we know that no value is `None` and it is safe to unwrap
        let x1 = self.x.unwrap();
        let y1 = self.y.unwrap();

        let x2 = other.x.unwrap();
        let y2 = other.y.unwrap();

        // We check if the 2 points represent a vertical line
        if x1 == x2 && (y1 + y2).is_zero() {
            // If yes, we return the point at infinity
            return Point::new(self.a, self.b, None, None);
        }

        // Compute the slope for the point
        let slope;

        if x1 == x2 && y1 == y2 {
            // If the 2 points are equal, we have a special case, where the line for the 2 points
            // is a tangent to the elliptic curve.

            // If the y coordinate is 0, we have special case and we return the point to infinity
            if y1.is_zero() {
                return Point::new(self.a, self.b, None, None);
            } else {
                // Otherwise, we compute the slope for the target, which is bassically the
                // derivative dy/dx on both sides of the equation
                slope = (x1.pow(2).mul_i64(3) + self.a) / (y1.mul_i64(2))
            }
        } else {
            // At this point, we know the points are differnt, and we compute the slope for
            // the line that passes through them both
            slope = (y2 - y1) / (x2 - x1)
        };

        // Compute x3
        let x3 = slope.pow(2) - x1 - x2;
        // Compute y3
        let y3 = slope * (x1 - x3) - y1;

        // Construct and return the point
        let p = Point::new(self.a, self.b, Some(x3), Some(y3)).expect("Not a point");
        Ok(p)
    }
}

impl<P: PointElement> Mul<u32> for Point<P> {
    type Output = Result<Self, PointError<P>>;

    fn mul(self, other: u32) -> Self::Output {
        // Using binary expansion
        let mut coefficient = other;
        let mut cache_result = self;
        let mut result_point = Point::new(self.a, self.b, None, None)?;

        while coefficient != 0 {
            if coefficient & 1 == 1 {
                result_point = (cache_result + result_point)?;
            }
            cache_result = (cache_result + cache_result)?;
            coefficient >>= 1;
        }

        Ok(result_point)
    }
}

impl<P: PointElement> Mul<U256> for Point<P> {
    type Output = Result<Self, PointError<P>>;

    fn mul(self, other: U256) -> Self::Output {
        // Using binary expansion
        let mut coefficient = other;

        let mut cache_result = self;
        let mut result_point = Point::new(self.a, self.b, None, None)?;

        while coefficient != U256::zero() {
            if coefficient & U256::one() == U256::one() {
                result_point = (cache_result + result_point)?;
            }
            cache_result = (cache_result + cache_result)?;
            coefficient >>= U256::one();
        }

        Ok(result_point)
    }
}

impl Add for Secp256K1Point {
    type Output = Result<Self, Secp256K1PointError>;

    fn add(self, other: Self) -> Self::Output {
        if self.order != other.order {
            return Err(Secp256K1PointError::DifferentGroupOrders(
                self.order,
                other.order,
            ));
        }

        Ok(Self {
            point: (self.point + other.point)?,
            order: self.order,
        })
    }
}

impl Mul<U256> for Secp256K1Point {
    type Output = Result<Self, Secp256K1PointError>;

    fn mul(self, other: U256) -> Self::Output {
        let other = other % self.order;
        Ok(Self {
            point: (self.point * other)?,
            order: self.order,
        })
    }
}

pub fn pow_mod(base: U256, exponent: U256, modulo: U256) -> U256 {
    // We use exponentiation by squaring
    // https://en.wikipedia.org/wiki/Exponentiation_by_squaring
    let mut value = U256::one();
    let mut cache_value = base;
    let mut local_exponent = exponent;
    while local_exponent != U256::zero() {
        if local_exponent & U256::one() != U256::zero() {
            value = value.mul_mod(cache_value, modulo);
        }
        local_exponent >>= 1;
        cache_value = cache_value.mul_mod(cache_value, modulo);
    }
    value
}

#[derive(Debug)]
pub enum PointError<P: PointElement> {
    NotOnCurve(P, P, P, P),
    DifferentCurves(P, P, P, P),
    InvalidCoordinate,
}

#[derive(Debug)]
pub struct Signature {
    // This represents the the target we are aiming for
    r: U256,
    s: U256,
}

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
const DER_MAX_LEN: usize = 4 * 1 + 33 + 2 * 1 + 33;

// Marker for the DER encoding, similar to a format magic
const DER_ENCODING_MARKER: u8 = 0x30;

// Marker for a value inside the DER encoding
const DER_VALUE_MARKER: u8 = 0x02;

// Takes a `U256` and encodes it as a DER format value
fn encode_der_value(value: U256) -> Result<Vec<u8>, EncodingError> {
    // instatiate an `array` we can use as buffer to store `value`'s bytes
    let mut value_buffer = [0; 32];
    // convert `value` into bytes and write them to the buffer
    value.to_big_endian(&mut value_buffer);
    // strip all leading zeros
    let mut value_bytes = value_buffer.into_iter().skip_while(|&x| x == 0).collect::<Vec<u8>>();

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
fn _encode_base58(value: U256) -> Result<String, EncodingError> {
    // We copy the value to make it mutable
    let mut value = value;
    // instatiate an `array` we can use as buffer to store `value`'s bytes
    let mut value_buffer = [0; 32];
    // convert `value` into bytes and write them to the buffer
    value.to_big_endian(&mut value_buffer);
    // Count all the leading zeros
    let leading_zeros = value_buffer.into_iter().take_while(|&x| x == 0).count();

    // Costruct a prefix of `1` (ones) which is the Base58 character for zero
    let prefix = std::iter::repeat('1').take(leading_zeros).collect::<String>();

    // Instantiate an empty string to store th result
    let mut encoding = String::from("");

    // While our value is not zero
    while value > U256::zero() {
        // Compute the remainder of the operation
        let remainder: usize = (value % _BASE58_ALPHABET.len()).as_usize();
        // Get the mapped value from the Base58 alphabet. Since we cannot inter string slices
        // because they are made up of UTF-8 characters, we need to do this
        let base58_char = _BASE58_ALPHABET.chars().nth(remainder).ok_or(EncodingError::OutOfRange)?;
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
}

/// Issues an error whenever encoding goes wrong
#[derive(Debug)]
pub enum EncodingError {
    ZeroLengthValue,
    OutOfRange,
}

#[derive(Clone, Copy, Debug)]
pub struct Secp256K1Point {
    point: Point<FieldElement<U256>>,
    order: U256,
}

impl Secp256K1Point {
    /// Creates a new generator point for this Bitcoin curve
    pub fn generator() -> Result<Self, Secp256K1PointError> {
        // X coordidinate for the Generator point
        let secp256k1_generator_x: U256 = U256::from_str_radix(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            16,
        )?;

        // Y coordinate for the Generator point
        let secp256k1_generator_y: U256 = U256::from_str_radix(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            16,
        )?;

        Self::new(secp256k1_generator_x, secp256k1_generator_y)
    }

    // Parses and extracts a new `Secp256K1Point` from a SEC format
    pub fn parse(sec_bytes: &[u8]) -> Result<Self, Secp256K1PointError> {
        let seckp256k1_prime: U256 = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )?;
        // First we read the marker from the data
        let marker = sec_bytes.get(0).ok_or(Secp256K1PointError::DataTooShort)?;

        // Afterwards we read the x-coordinate
        let x = U256::from_big_endian(
            sec_bytes
                .get(1..33)
                .ok_or(Secp256K1PointError::DataTooShort)?,
        );

        let x = FieldElement::new(x, seckp256k1_prime)?;

        // We obtain the y-coordinate in different ways, depending on the marker
        match marker {
            0x04 => {
                // This branch means the format is not compressed and the y-coordinate just follows
                // x
                let y = U256::from_big_endian(
                    sec_bytes
                        .get(33..65)
                        .ok_or(Secp256K1PointError::DataTooShort)?,
                );
                // Return the parsed point
                Self::new(x.value, y)
            }
            0x02 | 0x03 => {
                // We compute the right side of the equation y^2 = x^3 + 7
                let right_side =
                    x.pow(U256::from(3))? + FieldElement::new(U256::from(7), seckp256k1_prime)?;
                // We try and solve the left side
                let left_side = right_side.sqrt();

                let y_odd;
                let y_even;

                // Check if the y-coordinate is even. The equation we are computing has 2 possible
                // solutions, one is `y` and one is `p-y`.
                // Between the 2 values, since `p` is prime and odd and `y` can be both odd or even
                // there will always be 1 odd value and 1 even value for the solutions.
                // This `if` statement computes them both
                if left_side.value % U256::from(2) == U256::zero() {
                    y_even = left_side;
                    y_odd = FieldElement::<U256>::new(
                        seckp256k1_prime - left_side.value,
                        seckp256k1_prime,
                    )?;
                } else {
                    y_odd = left_side;
                    y_even = FieldElement::<U256>::new(
                        seckp256k1_prime - left_side.value,
                        seckp256k1_prime,
                    )?;
                }

                // Depending on what the marker says about the evenness of the value, we
                // instantiate with the correct `y`
                match marker {
                    0x02 => return Self::new(x.value, y_even.value),
                    0x03 => return Self::new(x.value, y_odd.value),
                    _ => return Err(Secp256K1PointError::UnknownMarker(*marker)),
                }
            }
            _ => Err(Secp256K1PointError::UnknownMarker(*marker)),
        }
    }

    // Returns the `point` representing a ECDSA Public Key in an uncompressed or compressed SEC
    // format. This serializes the point in a Big Endian format.
    pub fn sec(&self, compressed: bool) -> Result<Vec<u8>, Secp256K1PointError> {
        let mut sec;

        // Get the value of the x-coordinate
        let x = self
            .point
            .x
            .ok_or(Secp256K1PointError::CompressingNone)?
            .value;
        // Get the value of the y-coordinate
        let y = self
            .point
            .y
            .ok_or(Secp256K1PointError::CompressingNone)?
            .value;

        // Check if we want the compressed format
        if compressed == false {
            sec = [0; 65].to_vec();
            // First byte is the identifier for the sec uncompressed format
            sec[0] = 4;
            // Serialzie the x-coordinate as Big Endian
            x.to_big_endian(&mut sec[1..33]);
            // Serialzie the y-coordinate as Big Endian
            y.to_big_endian(&mut sec[33..65]);
        } else {
            sec = [0; 33].to_vec();

            if y % U256::from(2) == U256::zero() {
                // If y-coordinate is even, the marker is 0x02
                sec[0] = 0x02;
            } else {
                // If y-coordinate is odd, the marker is 0x03
                sec[0] = 0x03;
            }

            x.to_big_endian(&mut sec[1..33]);
        }

        // Return the result
        Ok(sec)
    }

    // Verifies that the signature hash `z` corresponds with the given `signature`
    pub fn verify(&self, z: U256, signature: Signature) -> Result<bool, Secp256K1PointError> {
        // Fetch the generator point for hte Bitcoin curve
        let generator = Secp256K1Point::generator()?;

        // Compute `s` to the power of `-1`, which in elliptic curve language is power of `N-2`
        let s_inv = pow_mod(signature.s, self.order - U256::from(2u8), self.order);

        // Compute `u` which is the scalar for the generator point G
        let u = z.mul_mod(s_inv, self.order);
        // Compute `v` which is the scalar for the Public key P
        let v = signature.r.mul_mod(s_inv, self.order);
        // Compute the left side of the sum
        let left = (generator * u)?;
        // Compute the right side of the sum
        let right = (*self * v)?;
        // Check if the target that we supplied earlier, represented by `r` is the the same we
        // obtained from the equation computed above
        let verified = (left + right)?
            .point
            .x
            .ok_or(PointError::InvalidCoordinate)?
            .value
            == signature.r;

        // Return the result
        Ok(verified)
    }

    /// Function used to construct a new Secp256K1 Point given the `x` and `y` coordinate as U256.
    pub fn new(x: U256, y: U256) -> Result<Self, Secp256K1PointError> {
        // Prime used to generate Finite Field Elements for the Bitcoin curve
        // 2**256 - 2**32 - 997
        let seckp256k1_prime: U256 = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )?;

        // Instantiate all elements as Finite fields
        let fe_x = FieldElement::<U256>::new(x, seckp256k1_prime)?;
        let fe_y = FieldElement::<U256>::new(y, seckp256k1_prime)?;
        let fe_a = FieldElement::<U256>::new(U256::zero(), seckp256k1_prime)?;
        let fe_b = FieldElement::<U256>::new(U256::from_str_radix("7", 10)?, seckp256k1_prime)?;

        // Instatiate the generator point
        let generator_point = Point::new(fe_a, fe_b, Some(fe_x), Some(fe_y))?;

        // Order of the Finite Field generated by the Generator Point above. Also represents the
        // scalar at which we find the point at inifinity
        let seckp256k1_order: U256 = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )?;

        Ok(Self {
            point: generator_point,
            order: seckp256k1_order,
        })
    }

    pub fn order(&self) -> U256 {
        self.order
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

    pub fn sign(&self, z: U256) -> Result<Signature, PrivateKeyError> {
        let k = self.deterministic_k(z);
        // Compute the x-coordinate of R, which is k*G
        let r = (self.generator * k)?
            .point
            .x
            .ok_or(PrivateKeyError::InvalidX)?
            .value;

        // Compute the inverse of k
        let k_inv = pow_mod(
            k,
            self.generator.order - U256::from(2u8),
            self.generator.order,
        );
        // Compute s=(z+r*e)/k
        let s =
            (z + r.mul_mod(self.secret, self.generator.order)).mul_mod(k_inv, self.generator.order);

        // Return the signature
        Ok(Signature::new(r, s))
    }

    fn deterministic_k(&self, z: U256) -> U256 {
        // Sequence of bytes filled with zero
        let k = [0; 32];
        // Sequence of bytes filled with one
        let v = [1; 32];

        let order = self.point.order;

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
        hmac_msg_slice.get_mut(0..32).unwrap().copy_from_slice(&v_hash);
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

#[derive(Debug)]
pub enum Secp256K1PointError {
    FromStrRadixErr(uint::FromStrRadixErr),
    FieldElementError(FieldElementError),
    PointErrorFieldElementU256(PointError<FieldElement<U256>>),
    DifferentGroupOrders(U256, U256),
    UnknownMarker(u8),
    CompressingNone,
    DataTooShort,
}

impl From<uint::FromStrRadixErr> for Secp256K1PointError {
    fn from(err: uint::FromStrRadixErr) -> Self {
        Self::FromStrRadixErr(err)
    }
}

impl From<FieldElementError> for Secp256K1PointError {
    fn from(err: FieldElementError) -> Self {
        Self::FieldElementError(err)
    }
}

impl From<PointError<FieldElement<U256>>> for Secp256K1PointError {
    fn from(err: PointError<FieldElement<U256>>) -> Self {
        Self::PointErrorFieldElementU256(err)
    }
}

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

#[cfg(test)]
mod tests {
    use super::double_sha256;
    use super::{Point, PrivateKey, Secp256K1Point, Signature, U256};
    use finite_field::FieldElement;

    #[test]
    fn test_eq() {
        let a = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let b = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ne() {
        let a = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let b = Point::new(5, 7, Some(18), Some(77)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_exercise1() {
        let a = 5;
        let b = 7;
        let pairs = [(2, 4), (-1, -1), (18, 77), (5, 7)];
        let not_on_curve = [(2, 4), (5, 7)];

        for (x, y) in pairs {
            if not_on_curve.contains(&(x, y)) {
                assert_eq!(false, Point::new(a, b, Some(x), Some(y)).is_ok());
            } else {
                assert_eq!(true, Point::new(a, b, Some(x), Some(y)).is_ok());
            }
        }
    }

    #[test]
    fn test_addition() {
        // These 2 points represent a vertical line
        let p1 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let p2 = Point::new(5, 7, Some(-1), Some(1)).unwrap();

        let infinity = Point::new(5, 7, None, None).unwrap();
        assert_eq!(
            (p1 + infinity).unwrap(),
            Point::new(5, 7, Some(-1), Some(-1)).unwrap()
        );
        assert_eq!(
            (p2 + infinity).unwrap(),
            Point::new(5, 7, Some(-1), Some(1)).unwrap()
        );
        assert_eq!((p1 + p2).unwrap(), Point::new(5, 7, None, None).unwrap());
    }

    #[test]
    fn exercise5() {
        let p1 = Point::new(5, 7, Some(2), Some(5)).unwrap();
        let p2 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();

        let p3 = Point::new(5, 7, Some(3), Some(-7)).unwrap();

        assert_eq!((p1 + p2).unwrap(), p3);
    }

    #[test]
    fn exercise6() {
        let p1 = Point::new(5, 7, Some(-1), Some(-1)).unwrap();
        let p2 = p1;

        let p3 = Point::new(5, 7, Some(18), Some(77)).unwrap();

        assert_eq!((p1 + p2).unwrap(), p3);
    }

    // The following tests are for FieldElement testing
    #[test]
    fn elliptic_curve_over_finite_fields_exercise1() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();

        let coordinates = [(192, 105), (17, 56), (200, 119), (1, 193), (42, 99)];
        let valid_points = [(192, 105), (17, 56), (1, 193)];

        for (x, y) in coordinates {
            let x1 = FieldElement::<i64>::new(x, 223).unwrap();
            let y1 = FieldElement::<i64>::new(y, 223).unwrap();
            let p1 = Point::new(a, b, Some(x1), Some(y1));

            if p1.is_ok() {
                assert!(valid_points.contains(&(x, y)));
            } else {
                assert!(!valid_points.contains(&(x, y)));
            }
        }
    }

    #[test]
    fn elliptic_curve_over_finite_fields_exercise2() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();

        let point_pairs = [
            ((192, 105), (17, 56), (170, 142)),
            ((170, 142), (60, 139), (220, 181)),
            ((47, 71), (17, 56), (215, 68)),
            ((143, 98), (76, 66), (47, 71)),
        ];

        for ((x1, y1), (x2, y2), (x3, y3)) in point_pairs {
            let x1 = FieldElement::<i64>::new(x1, 223).unwrap();
            let y1 = FieldElement::<i64>::new(y1, 223).unwrap();

            let x2 = FieldElement::<i64>::new(x2, 223).unwrap();
            let y2 = FieldElement::<i64>::new(y2, 223).unwrap();

            let x3 = FieldElement::<i64>::new(x3, 223).unwrap();
            let y3 = FieldElement::<i64>::new(y3, 223).unwrap();

            let p1 = Point::new(a, b, Some(x1), Some(y1)).unwrap();
            let p2 = Point::new(a, b, Some(x2), Some(y2)).unwrap();
            let p3 = Point::new(a, b, Some(x3), Some(y3)).unwrap();

            assert_eq!((p1 + p2).unwrap(), p3);
        }
    }

    #[test]
    fn elliptic_curve_over_finite_fields_exercise4() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x1 = FieldElement::<i64>::new(47, 223).unwrap();
        let y1 = FieldElement::<i64>::new(71, 223).unwrap();

        let p1 = Point::new(a, b, Some(x1), Some(y1)).unwrap();

        let finite_group_pairs = [
            (47, 71),
            (36, 111),
            (15, 137),
            (194, 51),
            (126, 96),
            (139, 137),
            (92, 47),
            (116, 55),
            (69, 86),
            (154, 150),
            (154, 73),
            (69, 137),
            (116, 168),
            (92, 176),
            (139, 86),
            (126, 127),
            (194, 172),
            (15, 86),
            (36, 112),
            (47, 152),
        ];

        for s in 1..21 {
            let (x, y) = finite_group_pairs.get(s - 1).unwrap();

            let x3 = FieldElement::<i64>::new(*x, 223).unwrap();
            let y3 = FieldElement::<i64>::new(*y, 223).unwrap();

            let p3 = (p1 * s as u32).unwrap();
            let p_result = Point::new(a, b, Some(x3), Some(y3)).unwrap();

            assert_eq!(p3, p_result);
        }
    }

    // TODO: Make a test to challenge the assertions made at page 51 by repeateadly substracting
    // the element from the left side of the equation to the element on the right side of the
    // equation
    #[test]
    fn test_reverse_scalar_multiplication() {
        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x1 = FieldElement::<i64>::new(47, 223).unwrap();
        let y1 = FieldElement::<i64>::new(71, 223).unwrap();
        let p_base = Point::new(a, b, Some(x1), Some(y1)).unwrap();

        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x2 = FieldElement::<i64>::new(47, 223).unwrap();
        let y2 = FieldElement::<i64>::new(71, 223).unwrap();
        let y_zero = FieldElement::<i64>::new(0, 223).unwrap();
        let p_to_sub = Point::new(a, b, Some(x2), Some(y_zero - y2)).unwrap();

        let a = FieldElement::<i64>::new(0, 223).unwrap();
        let b = FieldElement::<i64>::new(7, 223).unwrap();
        let x_res = FieldElement::<i64>::new(194, 223).unwrap();
        let y_res = FieldElement::<i64>::new(172, 223).unwrap();
        let p_res = Point::new(a, b, Some(x_res), Some(y_res)).unwrap();

        let mut times = 1;
        let mut p_right = p_res;

        // When should it finish if it does not have a solution?
        while p_right != p_base {
            p_right = (p_right + p_to_sub).unwrap();
            times += 1;
        }

        assert_eq!(17, times);
    }

    // Essentially this test if for making sure that the generator is on the curve
    #[test]
    fn test_seckp256k1field_new() {
        Secp256K1Point::generator().unwrap();
    }

    // Verify whether the generator point, G, has the order n
    #[test]
    fn test_seckp256k1_generator_has_order_n() {
        let generator_point = Secp256K1Point::generator().expect("Failed to get generator");
        // N represents the order of the group
        let n: U256 = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        // X and Y of this point should be `None`
        let _point_at_infinity = (generator_point * n).expect("Failed to multiply");
    }

    #[test]
    fn test_verify_signature() {
        let z = U256::from_str_radix(
            "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
            16,
        )
        .unwrap();
        let r = U256::from_str_radix(
            "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s = U256::from_str_radix(
            "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();
        let px = U256::from_str_radix(
            "04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
            16,
        )
        .unwrap();
        let py = U256::from_str_radix(
            "82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
            16,
        )
        .unwrap();

        let point = Secp256K1Point::new(px, py).unwrap();

        assert!(point.verify(z, Signature::new(r, s)).unwrap() == true);
    }

    #[test]
    fn test_verify_signature_exercise6() {
        let px = U256::from_str_radix(
            "887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c",
            16,
        )
        .unwrap();
        let py = U256::from_str_radix(
            "61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34",
            16,
        )
        .unwrap();
        let point = Secp256K1Point::new(px, py).unwrap();

        let pairs = [
            (
                "ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60",
                "ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395",
                "68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4",
            ),
            (
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
            ),
        ];

        for (z, r, s) in pairs.iter() {
            let z = U256::from_str_radix(z, 16).unwrap();
            let r = U256::from_str_radix(r, 16).unwrap();
            let s = U256::from_str_radix(s, 16).unwrap();

            assert!(point.verify(z, Signature::new(r, s)).unwrap() == true);
        }
    }

    #[test]
    fn test_sign_with_private_key() {
        let secret = U256::from_str_radix(
            "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
            16,
        )
        .unwrap();
        let priv_key = PrivateKey::new(secret).expect("Bad Private Key");
        let message = double_sha256(b"Alan Turing");

        assert_eq!(
            true,
            priv_key
                .point
                .verify(message, priv_key.sign(message).unwrap())
                .unwrap(),
        );
    }

    #[test]
    fn test_create_signature() {
        // This is an example of a brain wallet. This is a way to keep the private key, or rather
        // the stem or seed of the private key in your head without having to memorize something
        // too difficult.
        // TO NOT BE USED as a REAL SECRET.
        let e = double_sha256(b"my secret");
        // This is the signature hash, or the hash of the message that we are signing.
        let z = double_sha256(b"my message");

        // This is just for testing purposes
        let z_from_str = U256::from_str_radix(
            "231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78",
            16,
        )
        .unwrap();

        assert_eq!(z, z_from_str);

        // We are going to use a fixed `k` here, as a random value, for demonstration purposes.
        let k = U256::from(1234567890u64);

        // Fetch the generator point from the Bitcoin curve
        let generator = Secp256K1Point::generator().unwrap();

        // Compute the x-coordinate of R, which is k*G
        let r = (generator * k).unwrap().point.x.unwrap().value;
        let r_from_str = U256::from_str_radix(
            "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
            16,
        )
        .unwrap();
        assert_eq!(r_from_str, r);

        // Compute s=(z+r*e)/k
        use crate::pow_mod;
        use finite_field::Element;
        let k_inv = pow_mod(k, generator.order - U256::from(2u8), generator.order);

        let s = (z + r.mul_mod(e, generator.order)).mul_mod(k_inv, generator.order);
        let s_from_str = U256::from_str_radix(
            "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9",
            16,
        )
        .unwrap();
        assert_eq!(s_from_str, s);

        let point = (generator * e).unwrap();

        // Verifiy the signature that we got with the public key
        assert_eq!(true, point.verify(z, Signature::new(r, s)).unwrap());

        let point = point.point;
        let px_from_str = U256::from_str_radix(
            "028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
            16,
        )
        .unwrap();
        let py_from_str = U256::from_str_radix(
            "0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
            16,
        )
        .unwrap();
        assert_eq!(px_from_str, point.x.unwrap().value);
        assert_eq!(py_from_str, point.y.unwrap().value);
    }

    #[test]
    fn test_uncompressed_sec() {
        let sec_pairs = [
            (U256::from(5000), "testdata/ex1_5000"),
            (U256::from(2018_u128.pow(5)), "testdata/ex1_2018_pow_5"),
            (
                U256::from_str_radix("deadbeef12345", 16).unwrap(),
                "testdata/ex1_deadbeef12345",
            ),
        ];

        for (secret, filename) in sec_pairs {
            let private_key = PrivateKey::new(secret).expect("Cannot make private key");
            let sec_form = std::fs::read(filename).unwrap();
            assert_eq!(
                private_key.point.sec(false).unwrap().as_slice(),
                sec_form.as_slice()
            );
        }
    }

    #[test]
    fn test_compressed_sec() {
        let sec_pairs = [
            (U256::from(5001), "testdata/ex2_5001"),
            (U256::from(2019_u128.pow(5)), "testdata/ex2_2019_pow_5"),
            (
                U256::from_str_radix("deadbeef54321", 16).unwrap(),
                "testdata/ex2_deadbeef54321",
            ),
        ];

        for (secret, filename) in sec_pairs {
            let private_key = PrivateKey::new(secret).expect("Cannot make private key");
            let sec_form = std::fs::read(filename).unwrap();
            assert_eq!(
                private_key.point.sec(true).unwrap().as_slice(),
                sec_form.as_slice()
            );
        }
    }

    #[test]
    fn test_signature() {
        let r = U256::from_str_radix(
            "0000000000000000000000000000000000000000000000000000001abcdef",
            16,
        ).unwrap();
        let s = U256::from_str_radix(
            "0000000000000000000000000000000000000000000000000000000abcdef",
            16,
        ).unwrap();

        let sig = Signature::new(r, s);
        sig.der().unwrap();
    }

    #[test]
    fn test_der_ex3() {
        let r = U256::from_str_radix(
            "37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        ).unwrap();
        let s = U256::from_str_radix(
            "8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        ).unwrap();

        let sig = Signature::new(r, s);
        // Encode our signature with the DER format
        let der_encoding = sig.der().unwrap();

        // Read the result from the test file
        let der_enc_result = std::fs::read("testdata/ex3_der_encoded_sig.bin").unwrap();

        // Test if the 2 are equal
        assert_eq!(
            der_encoding,
            der_enc_result,
        );
    }

    #[test]
    fn test_base58_ex4() {
        let values = [
            (
                "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
                "testdata/base58_ex4_1.txt",
            ),
            (
                "eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c",
                "testdata/base58_ex4_2.txt",
            ),
            (
                "c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6",
                "testdata/base58_ex4_3.txt",
            ),
        ];

        for (hex_value, file_path) in values.iter() {
            let value = U256::from_str_radix(hex_value, 16).unwrap();
            let base58_encoding = crate::_encode_base58(value).unwrap();
            let mut correct_value = std::fs::read_to_string(file_path).unwrap();
            correct_value.pop();
            assert_eq!(base58_encoding, correct_value);
        }
    }
}
