use std::time::Duration;
use crate::hashing;
use crate::io::{Reader, ReaderError, BigEndian, LittleEndian};

/// Must be implemented by any type that has to be added as a transaction input
pub trait TxInput {}
/// Must be implemented by any type that has to be a transaction output
pub trait TxOutput {}

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

pub enum VersionError {
    MajorReadFailed,
}

impl From<ReaderError> for VersionError {
    fn from(err: ReaderError) -> Self {
        Self::MajorReadFailed
    }
}

/// Represents a Bitcoin transaction
pub struct Transaction<I: TxInput, O: TxOutput> {
    // Version of the transaction, indicating what additional features the transaction uses
    version: Version,
    // Inputs define what bitcoins are being spent
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
}
