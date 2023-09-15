use core::num::{TryFromIntError, ParseIntError};
use core::fmt::Debug;
use primitive_types::U256;
use crate::hashing;
use crate::utils::{decode_hex, Variant, VariantError};
use crate::io::{Reader, ReaderError, BigEndian, LittleEndian};
use std::collections::HashMap;
use serde::Deserialize;

/// Must be implemented by any type that has to be added as a transaction input
pub trait TxInput: Sized {
    type Error: Debug;
    // Provides the ability to parse the current object from a `Reader`
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error>;
    // Serialises `Self` into a structure of bytes, represented by `Vec<u8>`
    fn as_vec(&self) -> Result<Vec<u8>, Self::Error>;
    // Return the amount of this input, by referring to the previous transaction
    fn amount<O: TxOutput>(&self, tx_fetcher: &mut TxFetcher<Self, O>, testnet: bool) -> Result<u64, Self::Error>;
}
/// Must be implemented by any type that has to be a transaction output
pub trait TxOutput: Sized {
    type Error: Debug;
    // Parse `Self` from a `Reader` which is backed by a vector of bytes
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error>;
    // Serialises `Self` into a structure of bytes, represented by `Vec<u8>`
    fn as_vec(&self) -> Result<Vec<u8>, Self::Error>;
    // Return the amount of satoshis for this output
    fn amount(&self) -> u64;
}

/// Represents version of a transaction
#[derive(Debug)]
pub struct Version {
    major: u32,
}

impl Version {
    pub fn parse(reader: &mut Reader) -> Result<Self, VersionError> {
        let major = reader.read::<u32, BigEndian>()?;

        Ok(Self { major })
    }

    pub fn as_vec(self) -> Vec<u8> {
        self.major.to_le_bytes().to_vec()
    }
}

#[derive(Debug)]
pub enum VersionError {
    Reader(ReaderError)
}

impl From<ReaderError> for VersionError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
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
    // transaction output. This is a variable length field. Represents the key used to open the
    // locking script from the `Output`'s script pub key
    script_sig: Vec<u8>,
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
    TxFetch(TxFetchError),
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

impl From<TxFetchError> for InputError {
    fn from(err: TxFetchError) -> Self {
        Self::TxFetch(err)
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
        // Read the script signature
        let script_sig = reader.read_bytes(script_len)?.to_vec();
        // Sequence
        let seq = reader.read::<u32, LittleEndian>()?;

        Ok(Self {
            prev_tx_id,
            prev_tx_idx,
            script_sig,
            seq,
        })
    }

    // Return the amount of this input, by referring to the previous transaction
    fn amount<O: TxOutput>(&self, tx_fetcher: &mut TxFetcher<Self, O>, testnet: bool) -> Result<u64, Self::Error> {
        let prev_tx = tx_fetcher.fetch(self.prev_tx_id, testnet, false)?;
        let amount = prev_tx.outputs[usize::try_from(self.prev_tx_idx)?].amount();
        Ok(amount)
    }

    fn as_vec(&self) -> Result<Vec<u8>, Self::Error> {
        // Convert the script signature length to a `u64` so we can encode it as a Variant
        let script_len = u64::try_from(self.script_sig.len())?;
        // Compute the variant encoding of the length of the `script_sig` field
        let mut script_sig_variant = Variant::from(script_len).encode();

        // Compute the total size we need to allocate for our `Vec`
        let alloc_size = core::mem::size_of::<U256>() + core::mem::size_of::<u32>() +
            script_sig_variant.len() + self.script_sig.len() + core::mem::size_of::<u32>();

        // Allocate the Vec
        let mut serialized = Vec::with_capacity(alloc_size);

        // Resize and add the previous transaction id
        serialized.resize(core::mem::size_of::<U256>(), 0);
        self.prev_tx_id.to_little_endian(&mut serialized[0..core::mem::size_of::<U256>()]);

        // Convert the previous transaction index into a `Vec`
        let mut prev_tx_idx_bytes = self.prev_tx_idx.to_le_bytes().to_vec();
        // Append it to the serialized vector
        serialized.append(&mut prev_tx_idx_bytes);
        // Append the variant
        serialized.append(&mut script_sig_variant);
        // Append the script signature bytes
        serialized.extend_from_slice(&self.script_sig);

        // Convert the sequence field to bytes
        let mut seq_bytes = self.seq.to_le_bytes().to_vec();
        // Append the sequence bytes to serialized `Vec`
        serialized.append(&mut seq_bytes);

        Ok(serialized)
    }
}

impl Input {
    pub fn script_sig(&self) -> &[u8] {
        &self.script_sig
    }
}

pub struct Output {
    // Amount of bitcoins being assigned, and it is specified in Satoshis, or 1/100,000,000ths of
    // a bitcoin. The absolute maximum for the amount is the asymptotic limit of 21 million
    // bitcoins in satoshis, whic is 2,1 * 10.pow(5*3), or 2,100 trillion satoshis. This number is
    // > 2*32 and is thus stored in 64 bits, little endian serialised
    amount: u64,
    // A locked box that can only be opened by the holder of the key. It's like a one-way safe
    // that can receive deposits from anyone, but can only be opened by the owner of the safe.
    // This is a variable length field and is preceded by the length of the field in a variant.
    // Also called the locking script.
    script_pub_key: Vec<u8>,
}

impl TxOutput for Output {
    type Error = OutputError;
    fn parse(reader: &mut Reader) -> Result<Self, Self::Error> {
        // Read the amount as a u64
        let amount = reader.read::<u64, LittleEndian>()?;
        // Read the script pub key variant, which represents the length of the script pub key
        let script_pub_key_len = usize::try_from(Variant::parse(reader)?.as_u64())?;
        let script_pub_key = reader.read_bytes(script_pub_key_len)?.to_vec();

        Ok(Self {
            amount,
            script_pub_key,
        })
    }

    fn as_vec(&self) -> Result<Vec<u8>, Self::Error> {
        // First we need to represent the script pub key length as a `u64`
        let script_pub_key_len = u64::try_from(self.script_pub_key.len())?;
        // The lengths are encoded as `Variants` in order to save up space
        let mut script_pub_key_variant = Variant::from(script_pub_key_len).encode();

        // Now that we know all the sizes of the fields we want to serialize, we can compute the
        // entire size of the resulting `Vec`
        let vec_len =
            core::mem::size_of::<u64>() + script_pub_key_variant.len() + self.script_pub_key.len();
        // Allocate a `Vec` with the desired capacity
        let mut serialized = Vec::with_capacity(vec_len);

        // Convert `amount` to a vector of bytes we can serialize
        let mut amount_bytes = self.amount.to_le_bytes().to_vec();

        // Concatenate the bytes of the amount field
        serialized.append(&mut amount_bytes);
        // Concatenate the length of the variant
        serialized.append(&mut script_pub_key_variant);
        // Concatenate the script pub key
        serialized.extend_from_slice(&self.script_pub_key);

        Ok(serialized)
    }

    // Return the amount of satoshis for this output
    fn amount(&self) -> u64 { self.amount }
}

impl Output {
    pub fn script_pub_key(&self) -> &[u8] {
        &self.script_pub_key
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

/// Represents an element from one of the Witness' stack. See more on `Witness` documentation.
/// Each element on the stack is encoded a pair of a Variant and the actual data, that has the
/// length specified by that variant.
pub struct StackElement;

impl StackElement {
    /// Tries to read an encoded `StackElement` from an underlying `Reader` buffer
    pub fn parse(reader: &mut Reader) -> Result<Self, TxError> {
        // Read the length of the data for this element
        let data_len = Variant::parse(reader)?.as_u64();
        // Convert it into a `usize`
        let data_len = usize::try_from(data_len)?;
        // Read the data bytes, just for safety
        let _data = reader.read_bytes(data_len)?;

        Ok(Self)
    }
}

/// This structure represents the Witness from the segregated witness protocol. It is intended to
/// provide protection from transaction malleability and increase block capacity. Each witness has
/// a stack with a variable number of elements.
pub struct Witness {
    stack: Vec<StackElement>,
}

impl Witness {
    pub fn parse(reader: &mut Reader) -> Result<Self, TxError> {
        // Read the number of elements that the stack of this Witness has
        let elem_len = Variant::parse(reader)?.as_u64();
        // Convert it into a `usize`
        let elem_len = usize::try_from(elem_len)?;
        // Initialize a stack with the desired size
        let mut stack = Vec::with_capacity(elem_len);
        // We read each element from the reader
        for _ in 0..elem_len {
            let elem = StackElement::parse(reader)?;
            // Push the element onto the stack
            stack.push(elem);
        }

        // Initialize and return the Witness
        Ok(Self { stack })
    }

    pub fn stack(&self) -> &[StackElement] {
        &self.stack
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
#[derive(Copy, Clone)]
pub struct Locktime(u32);

impl Locktime {
    pub fn parse(reader: &mut Reader) -> Result<Self, ReaderError> {
        let value = reader.read::<u32, LittleEndian>()?;
        Ok(Self(value))
    }

    pub fn as_vec(&mut self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
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

    /// Return the locktime field
    pub fn locktime(&self) -> Locktime {
        self.locktime
    }

    /// Return the testnet field
    pub fn testnet(&self) -> bool {
        self.testnet
    }

    /// Computes and returns the fee as a difference between the `Transaction`'s inputs and outputs.
    /// This fee is sent to miners as an incentive to mine transactions.
    pub fn fee(&self) -> Result<u64, TxError> {
        // Create a new transaction fetcher, to fetch from the blockchain
        let mut tx_fetcher: TxFetcher<I, O> = TxFetcher::new();
        // Instantiate the total amount of inputs as 0
        let mut total_in_amount = 0u64;
        // Go through each of the inputs
        for tx_in in self.inputs.iter() {
            let curr_amount = tx_in.amount(&mut tx_fetcher, self.testnet)
                .map_err(|e| TxError::InputError(format!("{e:?}")))?;
            // Increment the value by that amount
            total_in_amount += curr_amount;
        }

        // Compute the total amount of outputs as a sum of each respective amount
        let total_out_amount = self.outputs.iter().fold(0u64, |acc, output| acc + output.amount());

        // Return the difference between the 2
        Ok(total_in_amount - total_out_amount)
    }

    pub fn encode(mut self) -> Result<Vec<u8>, TxError> {
        // We allocate a new `Vec` that will hold all the serialized data
        let mut serialized = vec![];

        // First we encode the version
        let mut version_bytes = self.version.as_vec();
        // Append it to the serialized `Vec`
        serialized.append(&mut version_bytes);

        // Convert the length of the inputs into a `u64`
        let input_len = u64::try_from(self.inputs.len())?;
        // Convert the length of the input into a variant and encode it
        let mut input_len_variant = Variant::from(input_len).encode();
        // Next we want to append the variant with length of the inputs
        serialized.append(&mut input_len_variant);

        // Next we go through each of the inputs and we serialize it
        for input in self.inputs.into_iter() {
            // Encode the inputs as a vector of bytes
            let mut input_bytes = input
                .as_vec()
                .map_err(|e| TxError::InputError(format!("{e:?}")))?;
            // Append it to the serialized vector
            serialized.append(&mut input_bytes);
        }

        // Convert the length of the outputs into a `u64`
        let output_len = u64::try_from(self.outputs.len())?;
        // Convert the length of the outputs into a variant and encode it
        let mut output_len_variant = Variant::from(output_len).encode();
        // Next we want to append the variant with length of the outputs
        serialized.append(&mut output_len_variant);

        // Next we go through each of the outputs and we serialize it
        for output in self.outputs.into_iter() {
            // Encode the inputs as a vector of bytes
            let mut output_bytes = output
                .as_vec()
                .map_err(|e| TxError::OutputError(format!("{e:?}")))?;
            // Append it to the serialized vector
            serialized.append(&mut output_bytes);
        }

        // Encode the locktime into a `Vec`
        let mut locktime_bytes = self.locktime.as_vec();
        // Append it to the serialized `Vec`
        serialized.append(&mut locktime_bytes);

        Ok(serialized)
    }

    /// Parse a new transaction from a sequence of bytes.
    pub fn from_reader(reader: &mut Reader, testnet: bool) -> Result<Self, TxError> {
        // Read the version
        let version = Version::parse(reader)?;

        // We peek a single byte
        let next_byte = reader.peek::<u8, LittleEndian>()?;

        // If that byte is 0x00, this means the transaction encoding also contains witness data.
        // To be more specific Segregated witness data.
        let has_segwit = next_byte == 0x00;

        // If it does, we also need to read another byte, that has to be 0x01. Since we did not
        // read the previous byte and we just picked it, we will read 2 bytes so we put the cursor
        // into the proper place
        if has_segwit {
            let segwit_flag = reader.read_bytes(2)?;
            // Check if the array matches our expectation
            if segwit_flag != [0x00, 0x01] {
                return Err(TxError::BadWitnessFlag);
            }
        }

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

        // At this point, we need to check if we have a witness flag.
        let _segwit = if has_segwit {
            // Initialize a stack with the desired size
            let mut segwits= Vec::with_capacity(inputs_len);
            // read each witness
            for _ in 0..inputs_len {
                let witness = Witness::parse(reader)?;
                segwits.push(witness);
            }
            Some(segwits)
        } else {
            None
        };

        // Read the locktime
        let locktime = Locktime::parse(reader)?;

        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
            testnet,
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
    Reqwest(reqwest::Error),
    ParseInt(ParseIntError),
    BadWitnessFlag,
    TxFetchFailed(U256),
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

pub struct TxFetcher<I: TxInput, O: TxOutput> {
    // Cached transaction IDs
    cache: HashMap<U256, Transaction<I, O>>,
}

/// Wraps a raw transaction, represented by a hex string
#[derive(Deserialize, Debug)]
pub struct RawTx {
    pub hex: String,
}

impl<I: TxInput, O: TxOutput> TxFetcher<I, O> {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }
    pub fn url(&self, testnet: bool) -> String {
        match testnet {
            true => "https://api.blockcypher.com/v1/btc/test3/txs".to_string(),
            false => "https://api.blockcypher.com/v1/btc/main/txs".to_string(),
        }
    }

    pub fn fetch(
        &mut self,
        tx_id: U256,
        testnet: bool,
        fresh: bool
    ) -> Result<&Transaction<I, O>, TxFetchError>{
        // If we are not requested to provide fresh info or we do not have the transaction id in
        // our cache
        if fresh || !self.cache.contains_key(&tx_id) {
            // Get the base url for the request
            let base_url = self.url(testnet);
            // Create the request with the transaction id
            let url = format!("{base_url}/{:x}", tx_id);

            // Build the request and execute it
            let response = reqwest::blocking::Client::new()
                .get(url)
                .query(&[("includeHex", "true")])
                .send()?;

            // Fetch the hex field of the response
            let raw_tx: RawTx = response.json()?;
            // We get the transaction in as a UTF-8 string with hex bytes in it. So we must convert
            // it to a u8 slice before parsing it.
            let raw_tx = decode_hex(raw_tx.hex.as_ref())?;
            // Create a reader from the raw transaction
            let mut reader = Reader::from_vec(raw_tx);
            // Parse the transaction from the reader
            let tx = Transaction::<I, O>::from_reader(&mut reader, testnet)?;
            // Insert the transaction into the cache
            self.cache.insert(tx_id, tx);
        }

        // Check if we have the transaction
        match self.cache.get(&tx_id) {
            // If we do, return it
            Some(cached_tx) => Ok(cached_tx),
            // If not, return an error
            None => Err(TxFetchError::TxFetchFailed(tx_id)),
        }
    }
}

#[derive(Debug)]
pub enum TxFetchError {
    ParseInt(ParseIntError),
    Reqwest(reqwest::Error),
    TxError(TxError),
    TxFetchFailed(U256),
}

impl From<ParseIntError> for TxFetchError {
    fn from(err: ParseIntError) -> Self {
        Self::ParseInt(err)
    }
}

impl From<reqwest::Error> for TxFetchError {
    fn from(err: reqwest::Error) -> Self {
        Self::Reqwest(err)
    }
}

impl From<TxError> for TxFetchError {
    fn from(err: TxError) -> Self {
        Self::TxError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{Transaction, Input, Output, TxOutput, TxFetcher};
    use crate::io::Reader;
    use primitive_types::U256;

    #[test]
    fn test_transaction_parsing() {
        let test_file = "testdata/transaction_ex5_pg58.bin";
        let tx_bytes = std::fs::read(test_file).expect("Failed to read test file");
        let mut tx_reader = Reader::from_vec(tx_bytes);

        let tx: Transaction<Input, Output> =
            Transaction::from_reader(&mut tx_reader, true).expect("Failed to parse the transaction");

        let script_pub_key = vec![
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
        ];
        assert_eq!(&script_pub_key, tx.outputs[0].script_pub_key());
        assert_eq!(4000_0000, tx.outputs[1].amount());
    }

    #[test]
    fn test_tx_fetcher() {
        let tx_id = U256::from_str_radix(
            "ea10065fa8de76bcb2e9a4f38b66eb6b7bd38c829a5d2426b4c6ebdcb486b3a9",
            16
        ).expect("Failed to convert transaction id");

        let mut tx_fetcher: TxFetcher<Input, Output> = TxFetcher::new();
        tx_fetcher.fetch(tx_id, true, true).expect("Failed to fetch transaction");
    }

    #[test]
    fn test_tx_fee() {
        let tx_id = U256::from_str_radix(
            "ea10065fa8de76bcb2e9a4f38b66eb6b7bd38c829a5d2426b4c6ebdcb486b3a9",
            16
        ).expect("Failed to convert transaction id");

        let mut tx_fetcher: TxFetcher<Input, Output> = TxFetcher::new();
        let tx = tx_fetcher.fetch(tx_id, true, true).expect("Failed to fetch transaction");

        let fee = tx.fee().expect("Failed to fetch fee for transaction");
        // The fee should be 147 satoshis, which is 1 satoshi per vByte, which is the weight of the
        // blocksize, given by the SegWit algorithm
        assert!(fee == 147);
    }
}
