use crate::sign::Signature;
use core::fmt::Debug;
use core::ops::{Add, Div, Mul, Sub};
use finite_field::{Element, FieldElement, FieldElementError};
use primitive_types::U256;
use crate::{hashing::hash160, serialise::{encode_base58_checksum, EncodingError}};

// Prefix used to be appended before computing the address which resided on the mainnet
const MAINNET_PREFIX: u8 = 0x00;
// Prefix used to be appended before computing the address which resided on the testnet
const TESTNET_PREFIX: u8 = 0x6f;

/// Represents a point on an elliptic curve.
/// We could make the curse a generic parameter?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point<P: PointElement> {
    a: P,
    b: P,
    x: Option<P>,
    y: Option<P>,
}

impl<P: PointElement> Point<P> {
    pub fn x(&self) -> Option<P> {
        self.x
    }

    pub fn y(&self) -> Option<P> {
        self.y
    }
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

    pub fn point(&self) -> Point<FieldElement<U256>> {
        self.point
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

    // Computes the `hash160` variant of the sec compressed format
    pub fn hash160(&self, compressed: bool) -> Result<Vec<u8>, Secp256K1PointError> {
        // Encode the point in the SEC format
        let sec = self.sec(compressed)?;

        // Hash the SEC encoding using the `hash160`
        let hash160_bytes = hash160(&sec);

        Ok(hash160_bytes)
    }

    /// Computes the Address Format of this point
    pub fn address(&self, compressed: bool, testnet: bool) -> Result<String, Secp256K1PointError> {
        // Compute the hash160 of the SEC format
        let mut hash160 = self.hash160(compressed)?;

        // Check if we are generating the address for a testnet
        let prefix = match testnet {
            true => TESTNET_PREFIX,
            false => MAINNET_PREFIX,
        };

        // Add the prefix to our hashed bytes
        hash160.insert(0, prefix);

        // Encode the result into a Base58 + checksum and return it
        Ok(encode_base58_checksum(&hash160)?)
    }

    // Verifies that the signature hash `z` corresponds with the given `signature`
    pub fn verify(&self, z: U256, signature: Signature) -> Result<bool, Secp256K1PointError> {
        // Fetch the generator point for hte Bitcoin curve
        let generator = Secp256K1Point::generator()?;

        // Compute `s` to the power of `-1`, which in elliptic curve language is power of `N-2`
        let s_inv = pow_mod(signature.s(), self.order - U256::from(2u8), self.order);

        // Compute `u` which is the scalar for the generator point G
        let u = z.mul_mod(s_inv, self.order);
        // Compute `v` which is the scalar for the Public key P
        let v = signature.r().mul_mod(s_inv, self.order);
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
            == signature.r();

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

#[derive(Debug)]
pub enum Secp256K1PointError {
    FromStrRadixErr(uint::FromStrRadixErr),
    FieldElementError(FieldElementError),
    PointErrorFieldElementU256(PointError<FieldElement<U256>>),
    DifferentGroupOrders(U256, U256),
    UnknownMarker(u8),
    CompressingNone,
    DataTooShort,
    EncodingError(EncodingError),
    FromUtf8Error(std::string::FromUtf8Error),
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

impl From<EncodingError> for Secp256K1PointError {
    fn from(err: EncodingError) -> Self {
        Self::EncodingError(err)
    }
}

impl From<std::string::FromUtf8Error> for Secp256K1PointError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::FromUtf8Error(err)
    }
}

impl From<PointError<FieldElement<U256>>> for Secp256K1PointError {
    fn from(err: PointError<FieldElement<U256>>) -> Self {
        Self::PointErrorFieldElementU256(err)
    }
}
