use core::num::TryFromIntError;
use std::time::Duration;
use primitive_types::U256;
use crate::hashing;
use crate::utils::{Variant, VariantError};
use crate::io::{Reader, ReaderError, BigEndian, LittleEndian};

/// Must be implemented by any type that has to be added as a transaction input
pub trait TxInput: Sized {
    type Error;
    // Provides the ability to parse the current object from a `Reader`
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error>;
}
/// Must be implemented by any type that has to be a transaction output
pub trait TxOutput: Sized {
    type Error;
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error>;
}

/// Represents version of a transaction
pub struct Version {
    major: u32,
}

impl Version {
    pub fn parse(reader: &mut Reader) -> Result<Self, VersionError> {
        let major = reader.read::<u32, BigEndian>()?;

        Ok(Self { major })
    }
}

#[derive(Debug)]
pub enum VersionError {
    MajorReadFailed,
}

impl From<ReaderError> for VersionError {
    fn from(err: ReaderError) -> Self {
        Self::MajorReadFailed
    }
}

/// Bitcoin's inputs are spending outputs of a previous transaction. Each input needs 2 things:
/// - A reference to bitcoins you received previously
/// - Proof that these are yours to spend
pub struct Input {
    // Previous transaction ID. Is the hash256(double sha256) of the previous transaction's
    // contents. This uniquely defines the previous transaction. LE encoded
    prev_tx_id: U256,
    // Previous transaction index. Identifies which output from the previous transaction we are
    // spending. In other words, which output from a previous transaction is used as input here.
    prev_tx_idx: u32,
    // Script signature. Opening a locked box-something that can only be done by the owner of the
    // transaction output. This is a variable length field
    script_sig: Option<Vec<u8>>,
    // Sequence, originally intended as a way to do what Satoshi called "high-frequency trades"
    // with the locktime field, but is currently used with Replace-By-Fee(RBF) and
    // OP_CHECKSEQUENCEVERIFY.
    seq: u32,
}

#[derive(Debug)]
pub enum InputError {
    Reader(ReaderError),
    Variant(VariantError),
    TryFromInt(TryFromIntError),
}

impl From<ReaderError> for InputError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
    }
}

impl From<VariantError> for InputError {
    fn from(err: VariantError) -> Self {
        Self::Variant(err)
    }
}

impl From<TryFromIntError> for InputError {
    fn from(err: TryFromIntError) -> Self {
        Self::TryFromInt(err)
    }
}

impl TxInput for Input {
    type Error = InputError;
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error> {
        // Read the previous transaction ID
        let prev_tx_id = U256::from_little_endian(reader.read_bytes(32)?);
        // Read the previous transaction Index
        let prev_tx_idx = reader.read::<u32, LittleEndian>()?;
        // Read the variant that tells us how long the script is
        let script_len = usize::try_from(Variant::parse(reader)?.as_u64())?;
        // We default to an empty script signature
        let script_sig = Some(reader.read_bytes(script_len)?.to_vec());
        // Sequence
        let seq = reader.read::<u32, LittleEndian>()?;

        Ok(Self {
            prev_tx_id,
            prev_tx_idx,
            script_sig,
            seq,
        })
    }
}

/// Represents a collection of multiple inputs
pub struct Inputs(Vec<Input>);

pub struct Output {
    // Amount of bitcoins being assigned, and it is specified in Satoshis, or 1/100,000,000ths of
    // a bitcoin. The absolute maximum for the amount is the asymptotic limit of 21 million
    // bitcoins in satoshis, whic is 2,1 * 10.pow(5*3), or 2,100 trillion satoshis. This number is
    // > 2*32 and is thus stored in 64 bits, little endian serialised
    amount: u64,
    // A locked box that can only be openede by the holder of the key. It's like a one-way safe
    // that can receive deposits from anyone, but can only be opened by the owner of the safe.
    // This is a variable length field and is preceded by the length of the field in a variant.
    script_pub_key: Option<Vec<u8>>,
}

impl TxOutput for Output {
    type Error = OutputError;
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error> {
        // Read the amount as a u64
        let amount = reader.read::<u64, LittleEndian>()?;
        // Read the script pub key variant, which represents the length of the script pub key
        let script_pub_key_len = usize::try_from(Variant::parse(reader)?.as_u64())?;
        let script_pub_key = Some(reader.read_bytes(script_pub_key_len)?.to_vec());

        Ok(Self {
            amount,
            script_pub_key,
        })
    }
}

#[derive(Debug)]
pub enum OutputError {
    Reader(ReaderError),
    Variant(VariantError),
    TryFromInt(TryFromIntError),
}

impl From<ReaderError> for OutputError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
    }
}

impl From<VariantError> for OutputError {
    fn from(err: VariantError) -> Self {
        Self::Variant(err)
    }
}

impl From<TryFromIntError> for OutputError {
    fn from(err: TryFromIntError) -> Self {
        Self::TryFromInt(err)
    }
}

/// Outputs define where the bitcoins are going.
pub struct Outputs(Vec<Output>);

/// Represents a Bitcoin transaction
pub struct Transaction<I: TxInput, O: TxOutput> {
    // Version of the transaction, indicating what additional features the transaction uses
    version: Version,
    // Inputs define what bitcoins are being spent. Bitcoin's inputs are spending outputs of a
    // previous transaction.
    inputs: I,
    // Outputs define where bitcoins are going
    outputs: O,
    // Locktime defines when this transaction start being valid
    locktime: Duration,
    // Specifies whether we are on the testnet or not
    testnet: bool,
}

impl<I: TxInput, O: TxOutput> Transaction<I, O> {
    /// Binary hash of the legacy serialization. This is the double sha256 hash of the
    /// serialization in little-endian.
    pub fn hash(&self) -> Vec<u8> {
        hashing::double_sha256(b"This is a pacemaker test")
    }

    /// Return the hexadecimal representation of this transaction's hash
    pub fn id(&self) -> String {
        self.hash().into_iter().fold(String::from(""), |acc, b| format!("{acc}{b:x}"))
    }

    pub fn from_reader(reader: &mut Reader) -> Result<(), TxError> {
        let version = Version::parse(reader)?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum TxError {
    Version(VersionError),
}

impl From<VersionError> for TxError {
    fn from(err: VersionError) -> Self {
        Self::Version(err)
    }
}
