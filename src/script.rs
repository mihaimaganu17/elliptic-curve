use std::{
    num::TryFromIntError,
    convert::AsRef,
};
use crate::{
    io::{LittleEndian, Reader, ReaderError},
    utils::{Variant, VariantError},
};

/// Stack-based programming language which defines how bitcoins are spent. It processes one command
/// at a time. The commands operate on a stack of elements. This struct can parse both the
/// `script_pub_key` and the `script_sig`.
#[derive(Debug)]
pub struct Script {
    // The commands that operate on the stack.
    // Processing stack of the `Script` programming language. After all the commands are evaluated,
    // the top element of the stack must be nonzero for the script to resolve as valid.
    cmds: Stack,
    // Hold the size of the underlying data that makes this structure. This is mostly for
    // convinience when we need a fast path for serialisation
    size: usize,
}

impl Script {
    /// Parses the script from a reader
    pub fn parse(reader: &mut Reader) -> Result<Self, ScriptError> {
        // Read the length of the entire script
        let script_len = usize::try_from(Variant::parse(reader)?.as_u64())?;
        // Instantiate vector of commands
        let mut cmds = vec![];
        // Currently we do not have any bytes read
        let mut bytes_read = 0;
        while bytes_read < script_len {
            // Read a byte and turn it into an operation
            let opcode_byte = reader.read::<u8, LittleEndian>()?;
            // Increase the number of read bytes
            bytes_read += core::mem::size_of::<u8>();
            match opcode_byte {
                opcode::OP_SPECIAL_START..=opcode::OP_SPECIAL_END => {
                    // Read the required bytes
                    let bytes = reader.read_bytes(opcode_byte.into())?;
                    // Create an element from them
                    let element = Element::from_slice(bytes);
                    // Add the element to the sequence of commands
                    cmds.push(Command::from_elem(element));
                    // Increated the count of read bytes
                    bytes_read += usize::from(opcode_byte);
                }
                opcode::OP_PUSHDATA1 => {
                    // Read how many bytes the data has
                    let bytes_to_read: usize = reader.read::<u8, LittleEndian>()?.into();
                    // Incread the number of read bytes
                    bytes_read += core::mem::size_of::<u8>();
                    // Read the required bytes
                    let bytes = reader.read_bytes(bytes_to_read)?;
                    // Create an element from them
                    let element = Element::from_slice(bytes);
                    // Add the element to the sequence of commands
                    cmds.push(Command::from_elem(element));
                    // Increated the count of read bytes
                    bytes_read += bytes_to_read;
                }
                opcode::OP_PUSHDATA2 => {
                    // Read how many bytes the data has
                    let bytes_to_read: usize = reader.read::<u16, LittleEndian>()?.into();
                    // Incread the number of read bytes
                    bytes_read += core::mem::size_of::<u16>();
                    // Read the required bytes
                    let bytes = reader.read_bytes(bytes_to_read)?;
                    // Create an element from them
                    let element = Element::from_slice(bytes);
                    // Add the element to the sequence of commands
                    cmds.push(Command::from_elem(element));
                    // Increated the count of read bytes
                    bytes_read += bytes_to_read;
                }
                _ => {
                    let cmd = Command::from_op(Opcode::from(opcode_byte));
                    cmds.push(cmd);
                }
            }
        }

        if bytes_read != script_len {
            return Err(ScriptError::ParsingScriptFailed);
        }

        Ok(Self {
            cmds: Stack::from_vec(cmds),
            size: script_len,
        })
    }

    /// Serialize the current object in the given `buffer`
    pub fn serialise(&self, buffer: &mut Vec<u8>) -> Result<(), ScriptError> {
        // Encode the length of the buffer
        let len = Variant::from(u64::try_from(self.size)?);
        buffer.extend_from_slice(&len.as_u64().to_le_bytes());
        self.cmds.serialise(buffer)?;
        Ok(())
    }

    pub fn to_vec(self) -> Result<Vec<u8>, ScriptError> {
        let mut buffer = vec![];
        self.serialise(&mut buffer)?;
        Ok(buffer)
    }
}

#[derive(Debug)]
pub enum ScriptError {
    ParsingScriptFailed,
    Variant(VariantError),
    Reader(ReaderError),
    TryFromInt(TryFromIntError),
    Stack(StackError),
}

impl From<VariantError> for ScriptError {
    fn from(err: VariantError) -> Self {
        Self::Variant(err)
    }
}

impl From<ReaderError> for ScriptError {
    fn from(err: ReaderError) -> Self {
        Self::Reader(err)
    }
}

impl From<TryFromIntError> for ScriptError {
    fn from(err: TryFromIntError) -> Self {
        Self::TryFromInt(err)
    }
}

impl From<StackError> for ScriptError {
    fn from(err: StackError) -> Self {
        Self::Stack(err)
    }
}

/// Represent the processing stack for the `Script` programming language. It is essentially a
/// wrapper againg a sequence of elements.
#[derive(Debug)]
pub struct Stack(Vec<Command>);

impl Stack {
    /// Create a new empty stack
    pub fn new() -> Self {
        Self(vec![])
    }

    /// Create a new stack from an existing vector of elements
    pub fn from_vec(vec: Vec<Command>) -> Stack {
        Self(vec)
    }

    /// Return the length of the stack
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Push an element to the top of the stack
    pub fn push(&mut self, cmd: Command) {
        self.0.push(cmd);
    }

    /// Bit-wise copies and returns the top element of the stack or `None` if the stack is empty
    pub fn top(&self) -> Option<Command> {
        self.0.get(self.0.len() - 1).cloned()
    }

    /// Pop the element from the top of the stack
    pub fn pop(&mut self) -> Option<Command> {
        self.0.pop()
    }

    pub fn serialise(&self, buffer: &mut Vec<u8>) -> Result<(), StackError> {
        for cmd in self.0.iter() {
            cmd.serialise(buffer)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum StackError {
    Command(CommandError),
}

impl From<CommandError> for StackError {
    fn from(err: CommandError) -> Self {
        Self::Command(err)
    }
}

/// Represents a command processed by the `Script` programming language
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Element(Element),
    Opcode(Opcode),
}

impl Command {
    pub fn from_elem(element: Element) -> Self {
        Self::Element(element)
    }

    pub fn from_op(opcode: Opcode) -> Self {
        Self::Opcode(opcode)
    }

    pub fn serialise(&self, buffer: &mut Vec<u8>) -> Result<(), CommandError> {
        match self {
            Self::Element(elem) => elem.serialise(buffer)?,
            Self::Opcode(opcode) => buffer.push(opcode.as_u8()),
        };
        Ok(())
    }
}

#[derive(Debug)]
pub enum CommandError {
    Element(ElementError),
    Opcode(OpcodeError),
}

impl From<ElementError> for CommandError {
    fn from(err: ElementError) -> Self {
        Self::Element(err)
    }
}

impl From<OpcodeError> for CommandError {
    fn from(err: OpcodeError) -> Self {
        Self::Opcode(err)
    }
}

pub const MAX_ELEMENT_SIZE: usize = 520;

/// Element represents data. Technically, processing an element pushed that element onto the stack
/// Elements are byte strings of lenght 1 to 520. A typical element might be a DER signature or a
/// SEC pubkey.
/// Element is backed by an array since the data has to be copied in some instances.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    data: Vec<u8>,
}

impl Element {
    /// Creates a new element by consuming `vec`
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Self { data: vec }
    }

    /// Creates a new element by allocating a new `vec` and copying the passed slices
    pub fn from_slice(slice: &[u8]) -> Self {
        Self { data: slice.to_vec() }
    }

    /// Serialise the current element into a slice of bytes
    pub fn serialise(&self, buffer: &mut Vec<u8>) -> Result<(), ElementError> {
        // Each element represents a sequence of data, which is encoded different based on size.
        // First we get the length of the data
        let len = self.data.len();

        // If the data length is 0, something is wrong and this should not be encoded
        if len == 0 {
            return Err(ElementError::ZeroSizedElement);
        } else if len <= opcode::OP_SPECIAL_END as usize {
            // We encode the length as a single byte
            buffer.push(len as u8);
        } else if len > opcode::OP_SPECIAL_END as usize && len < 0x100 {
            // We first need to push a special opcode specifying that we encode the length as a
            // single byte
            buffer.push(opcode::OP_PUSHDATA1);
            // We encode the length as a single byte
            buffer.push(len as u8);
        } else if len >= 0x100 && len <= 520 {
            // We first need to push a special opcode specifying that we encode the length as 2
            // bytes
            buffer.push(opcode::OP_PUSHDATA2);
            // We encode the length as 2 bytes
            buffer.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            return Err(ElementError::ElementTooLong(len));
        }
        // Encode the actual data
        buffer.extend_from_slice(&self.data);
        // Return successfully
        Ok(())
    }
}

impl AsRef<[u8]> for Element {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug)]
pub enum ElementError {
    ZeroSizedElement,
    ElementTooLong(usize),
}

/// Opcodes process the data. They consume 0 or more elements from the processing stack and push
/// zero or more elementes back to the stack.
#[derive(Debug, Clone, PartialEq)]
pub enum Opcode {
    // Specifies the OP_DUP operation, which duplicates the top element of the stack
    Dup,
    Hash256,
    Hash160,
    EqualVerify,
    CheckSig,
    // Specified a NO_OP operation
    Nop,
}

#[derive(Debug)]
pub enum OpcodeError {}

impl Opcode {
    /// Executes the current operation, by consuming it. A failed operation will return `false` and
    /// it will automatically fail script evaluation.
    pub fn execute(self, stack: &mut Stack) -> bool {
        match self {
            Self::Dup => op_dup(stack),
            Self::Hash160=> op_hash160(stack),
            Self::Hash256=> op_hash256(stack),
            // If the operation is not yet supported, we just return `false` as a mean to tell that
            // the operation failed
            _ => false,
        }
    }

    /// Return the Opcode value as encoded as a single `u8`
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Dup => opcode::OP_DUP,
            Self::Hash160 => opcode::OP_HASH160,
            Self::Hash256 => opcode::OP_HASH256,
            Self::EqualVerify => opcode::OP_EQUALVERIFY,
            Self::CheckSig => opcode::OP_CHECKSIG,
            // If the operation is not yet supported, we just initialize a no op
            Self::Nop => opcode::OP_NOP,
        }
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        match value {
            opcode::OP_DUP => Self::Dup,
            opcode::OP_HASH160 => Self::Hash160,
            opcode::OP_HASH256 => Self::Hash256,
            opcode::OP_EQUALVERIFY => Self::EqualVerify,
            opcode::OP_CHECKSIG => Self::CheckSig,
            // If the operation is not yet supported, we just initialize a no op
            _ => Self::Nop,
        }
    }
}

/// Implements duplication of the top element of the stack
pub fn op_dup(stack: &mut Stack) -> bool {
    if stack.len() < 1 {
        false
    } else {
        let maybe_elem = stack.top();
        if let Some(elem) = maybe_elem {
            stack.push(elem);
            true
        } else {
            false
        }
    }
}

/// Implements a double round of sha256 over the top element of the stack and pushed the result
/// onto the stack
pub fn op_hash256(stack: &mut Stack) -> bool {
    if stack.len() < 1 {
        false
    } else {
        let maybe_elem = stack.pop();
        if let Some(Command::Element(elem)) = maybe_elem {
            let hashed_vec = crate::hashing::double_sha256(elem.as_ref());
            let hashed_elem_cmd = Command::from_elem(Element::from_vec(hashed_vec));
            stack.push(hashed_elem_cmd);
            true
        } else {
            false
        }
    }
}

/// Implements the sha256 followed by ripemd160 hashing over the first element of the stack and
/// pushes the result to the stack
pub fn op_hash160(stack: &mut Stack) -> bool {
    if stack.len() < 1 {
        false
    } else {
        let maybe_elem = stack.pop();
        if let Some(Command::Element(elem)) = maybe_elem {
            let hashed_vec = crate::hashing::hash160(elem.as_ref());
            let hashed_elem = Command::from_elem(Element::from_vec(hashed_vec));
            stack.push(hashed_elem);
            true
        } else {
            false
        }
    }
}

// List of opcodes provided as constants that indicate what operation to perform
mod opcode {
    // An empty array of bytes is pushed onto the stack. This is not a no-op; an item is added to
    // the stack.
    pub const OP_0: u8 = 0x00;
    pub const OP_FALSE: u8 = 0x00;
    // Between 0x01 and 0x4b the next opcode bytes is data to be pushed onto the stack. This means
    // the when we encounter a value in this range, we read that many bytes
    pub const OP_SPECIAL_START: u8 = 0x01;
    pub const OP_SPECIAL_END: u8 = 0x4b;
    // The next byte contains the number of bytes to be pushed onto the stack. Since we already
    // have the special range above, this applies to element lengths between 76 and 255 bytes.
    pub const OP_PUSHDATA1: u8 = 0x4c;
    // The next 2 bytes contain the number of bytes to be pushed onto the stack. This is for
    // anything between 256 and 520 byte inclusive.
    pub const OP_PUSHDATA2: u8 = 0x4d;
    // The next 4 bytes contain the number of bytes to be pushed onto the stack.
    pub const OP_PUSHDATA4: u8 = 0x4e;
    // The number -1 is pushed onto the stack.
    pub const OP_1NEGATE: u8 = 0x4f;
    // The number 1 is pushed onto the stack.
    pub const OP_1: u8 = 0x51;
    pub const OP_TRUE: u8 = 0x51;
    // Opcode to specify a no op
    pub const OP_NOP: u8 = 0x61;
    // Opcode duplicates the top element of the stack
    pub const OP_DUP: u8 = 0x76;
    // Same as OP_EQUAL, but runs OP_VERIFY afterward.
    pub const OP_EQUALVERIFY: u8 = 0x88;

    // Crypto functions
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    // The entire transaction's outputs, inputs, and script (from the most recently-executed 
    // OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid
    // signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
    pub const OP_CHECKSIG: u8 = 0xac;
}

#[cfg(test)]
mod tests {
    use crate::script::{Command, Element, Stack, op_dup};

    #[test]
    fn test_op_dup() {
        let mut stack = Stack::new();
        let elem1 = Command::from_elem(Element::from_vec(vec![1, 2, 3, 4]));
        let elem2 = Command::from_elem(Element::from_vec(vec![5, 6, 7, 8]));
        stack.push(elem1);
        stack.push(elem2.clone());
        assert!(op_dup(&mut stack) == true);

        for _idx in 0..2 {
            assert!(stack.pop().unwrap() == elem2);
        }
    }
}
