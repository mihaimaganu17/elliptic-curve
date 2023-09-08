use core::num::TryFromIntError;
use core::fmt::Debug;
use std::time::Duration;
use primitive_types::U256;
use crate::hashing;
use crate::utils::{Variant, VariantError};
use crate::io::{Reader, ReaderError, BigEndian, LittleEndian};

/// Must be implemented by any type that has to be added as a transaction input
pub trait TxInput: Sized {
    type Error: Debug;
    // Provides the ability to parse the current object from a `Reader`
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error>;
}
/// Must be implemented by any type that has to be a transaction output
pub trait TxOutput: Sized {
    type Error: Debug;
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
    pub script_sig: Option<Vec<u8>>,
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

pub struct Output {
    // Amount of bitcoins being assigned, and it is specified in Satoshis, or 1/100,000,000ths of
    // a bitcoin. The absolute maximum for the amount is the asymptotic limit of 21 million
    // bitcoins in satoshis, whic is 2,1 * 10.pow(5*3), or 2,100 trillion satoshis. This number is
    // > 2*32 and is thus stored in 64 bits, little endian serialised
    pub amount: u64,
    // A locked box that can only be openede by the holder of the key. It's like a one-way safe
    // that can receive deposits from anyone, but can only be opened by the owner of the safe.
    // This is a variable length field and is preceded by the length of the field in a variant.
    pub script_pub_key: Option<Vec<u8>>,
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

/// Locktime is a way to time-delay a transaction. A transaction with a locktime of 600,000 cannot
/// go into the blockchain until block 600,001.
/// If the locktime is >= 500,000,000 it represents a Unix timestamp.
/// If it is < 500,000,000, it's a block number.
/// Given thin, transactions can be signed but unspendable until a certain point in Unix time or
/// block height is reached.
///
/// Note: Locktime is ignored if the sequence numbers for every input are 0xffff_ffff.
///
/// Caveat: The sender can spend the inputs prior to the locktime transaction getting into the
/// blockchain, thus invalidating the transaction at locktime.
///
/// The uses before BIP0065 were limited. BIP0065 introduces OP_CHECKLOCKTIMEVERIFY, which makes
/// locktime more useful by making an output unspendable until a ceratin locktime.
pub struct Locktime(u32);

impl Locktime {
    pub fn parse(reader: &mut Reader) -> Result<Self, ReaderError> {
        let value = reader.read::<u32, LittleEndian>()?;
        Ok(Self(value))
    }
}

/// Represents a Bitcoin transaction
pub struct Transaction<I: TxInput, O: TxOutput> {
    // Version of the transaction, indicating what additional features the transaction uses
    version: Version,
    // Inputs define what bitcoins are being spent. Bitcoin's inputs are spending outputs of a
    // previous transaction.
    pub inputs: Vec<I>,
    // Outputs define where bitcoins are going
    pub outputs: Vec<O>,
    // Locktime defines when this transaction start being valid
    locktime: Locktime,
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

    pub fn from_reader(reader: &mut Reader) -> Result<Self, TxError> {
        // Read the version
        let version = Version::parse(reader)?;

        // Read the number of inputs that the transaction has
        let inputs_len = Variant::parse(reader)?.as_u64();
        // Convert it into a `usize`
        let inputs_len = usize::try_from(inputs_len)?;

        // Instantiate a new `Vec` that will hold all the inputs
        let mut inputs: Vec<I> = Vec::with_capacity(inputs_len);
        // Based on this information, read the inputs
        for _idx in 0..inputs_len {
            inputs.push(I::parse(reader).map_err(|e| TxError::InputError(format!("{e:?}")))?);
        }

        // Read the number of outputs that the transaction has
        let outputs_len = Variant::parse(reader)?.as_u64();
        // Convert it into a `usize`
        let outputs_len = usize::try_from(outputs_len)?;


        // Instantiate a new `Vec` that will hold all the outputs
        let mut outputs: Vec<O> = Vec::with_capacity(outputs_len);
        // Based on this information, read the outputs
        for _idx in 0..outputs_len {
            outputs.push(O::parse(reader).map_err(|e| TxError::OutputError(format!("{e:?}")))?);
        }

        // Read the locktime
        let locktime = Locktime::parse(reader)?;

        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
            testnet: true,
        })
    }
}

#[derive(Debug)]
pub enum TxError {
    Version(VersionError),
    Reader(ReaderError),
    Variant(VariantError),
    TryFromInt(TryFromIntError),
    InputError(String),
    OutputError(String),
}

impl From<ReaderError> for TxError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
    }
}

impl From<VariantError> for TxError {
    fn from(err: VariantError) -> Self {
        Self::Variant(err)
    }
}

impl From<TryFromIntError> for TxError {
    fn from(err: TryFromIntError) -> Self {
        Self::TryFromInt(err)
    }
}

impl From<VersionError> for TxError {
    fn from(err: VersionError) -> Self {
        Self::Version(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{Transaction, Input, Output};
    use crate::io::Reader;

    #[test]
    fn test_transaction_parsing() {
        let test_file = "testdata/transaction_ex5_pg58.bin";
        let tx_bytes = std::fs::read(test_file).expect("Failed to read test file");
        let mut tx_reader = Reader::from_vec(tx_bytes);

        let tx: Transaction<Input, Output> =
            Transaction::from_reader(&mut tx_reader).expect("Failed to parse the transaction");

        let script_pub_key = Some(vec![
                0x76,
                0xa9,
                0x14,
                0xab,
                0xc,
                0xb,
                0x2e,
                0x98,
                0xb1,
                0xab,
                0x6d,
                0xbf,
                0x67,
                0xd4,
                0x75,
                0xb,
                0xa,
                0x56,
                0x24,
                0x49,
                0x48,
                0xa8,
                0x79,
                0x88,
                0xac,
            ]
        );
        assert_eq!(script_pub_key, tx.outputs[0].script_pub_key);
        assert_eq!(4000_0000, tx.outputs[1].amount);
    }
}
