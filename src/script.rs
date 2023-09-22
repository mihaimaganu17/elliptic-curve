mod op;

use core::ops::Add;
use std::{
    num::TryFromIntError,
    convert::AsRef,
};
use crate::{
    io::{LittleEndian, Reader, ReaderError},
    utils::{Variant, VariantError},
};
use op::{Opcode, opcode, OpcodeError};

/// Stack-based programming language which defines how bitcoins are spent. It processes one command
/// at a time. The commands operate on a stack of elements. This struct can parse both the
/// `script_pub_key` and the `script_sig`.
#[derive(Debug)]
pub struct Script {
    // The commands that operate on the stack.
    // Processing stack of the `Script` programming language. After all the commands are evaluated,
    // the top element of the stack must be nonzero for the script to resolve as valid.
    cmds: Vec<Command>,
    // Hold the size of the underlying data that makes this structure. This is mostly for
    // convinience when we need a fast path for serialisation
    size: usize,
}

impl Script {
    pub fn from_vec(vec: Vec<u8>) -> Result<Self, ScriptError> {
        let mut reader = Reader::from_vec(vec);
        Self::parse(&mut reader)
    }

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
            cmds: cmds,
            size: script_len,
        })
    }

    /// Serialize the current object in the given `buffer`
    pub fn serialise(&self, buffer: &mut Vec<u8>) -> Result<(), ScriptError> {
        // Encode the length of the buffer
        let len = Variant::from(u64::try_from(self.size)?);
        buffer.extend_from_slice(&len.encode());
        for cmd in self.cmds.iter() {
            cmd.serialise(buffer)?;
        }
        Ok(())
    }

    pub fn to_vec(self) -> Result<Vec<u8>, ScriptError> {
        let mut buffer = vec![];
        self.serialise(&mut buffer)?;
        Ok(buffer)
    }

    /// Return the 2 parts of the object as a `Stack` and the size
    pub fn into_parts(self) -> (Vec<Command>, usize){
        (self.cmds, self.size)
    }

    /// Evaluates the contents of the script, consuming them and using the given `stack`,
    /// returning the last element of the stack
    pub fn evaluate(&self, stack: &mut Stack) -> Result<bool, ScriptError> {
        // Go through each command for the current script
        for cmd in self.cmds.iter() {
            let executed = match cmd {
                Command::Opcode(opcode) => opcode.execute(stack),
                Command::Element(elem) => {
                    stack.push(elem.clone());
                    true
                }
            };
            if executed == false {
                return Ok(executed);
            }
        }
        // By the end of the script evaluation, if there is no element on the stack, return false
        if stack.len() == 0 {
            return Ok(false);
        }
        // Since we are here, there is definetly an element on the stack
        if let Some(elem) = stack.top() {
            // If that element is empty
            if elem.is_empty() {
                // Return false
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Add<Self> for Script {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let (mut left_cmds, left_size) = self.into_parts();
        let (mut right_cmds, right_size) = rhs.into_parts();
        left_cmds.append(&mut right_cmds);
        let size = left_size + right_size;
        Self { cmds: left_cmds, size }
    }
}

#[derive(Debug)]
pub enum ScriptError {
    ParsingScriptFailed,
    Variant(VariantError),
    Command(CommandError),
    Reader(ReaderError),
    TryFromInt(TryFromIntError),
    Stack(StackError),
}

impl From<VariantError> for ScriptError {
    fn from(err: VariantError) -> Self {
        Self::Variant(err)
    }
}

impl From<CommandError> for ScriptError {
    fn from(err: CommandError) -> Self {
        Self::Command(err)
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
pub struct Stack(Vec<Element>);

impl Stack {
    /// Create a new empty stack
    pub fn new() -> Self {
        Self(vec![])
    }

    /// Create a new stack from an existing vector of elements
    pub fn from_vec(vec: Vec<Element>) -> Stack {
        Self(vec)
    }

    /// Return the length of the stack
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Push an element to the top of the stack
    pub fn push(&mut self, elem: Element) {
        self.0.push(elem);
    }

    /// Bit-wise copies and returns the top element of the stack or `None` if the stack is empty
    pub fn top(&self) -> Option<Element> {
        self.0.get(self.0.len() - 1).cloned()
    }

    /// Pop the element from the top of the stack
    pub fn pop(&mut self) -> Option<Element> {
        self.0.pop()
    }

    pub fn into_inner(self) -> Vec<Element> {
        self.0
    }
}

impl Add<Self> for Stack {
    type Output = Stack;
    fn add(self, rhs: Self) -> Self::Output {
        let mut base_vec = self.into_inner();
        base_vec.append(&mut rhs.into_inner());
        Stack::from_vec(base_vec)
    }
}

#[derive(Debug)]
pub enum StackError {
    Element(ElementError),
}

impl From<ElementError> for StackError {
    fn from(err: ElementError) -> Self {
        Self::Element(err)
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

/// Element represents data. Technically, processing an element is equivalent to pushing that
/// element onto the stack. Elements are byte strings of lenght 1 to 520. A typical element might
/// be a DER signature or a SEC pubkey.
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

    /// Check if the underlying data is empty
    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Encode a numerical value as an element to be pushed on the stack. Currently there seems no
    /// need to encode something other than a singned 64-bit integer.
    pub fn from_integer(value: i64) -> Self {
        if value == 0 {
            return Self { data: vec![] };
        }
        // Get the absolute value of the value
        let mut abs_value = value.abs();
        // Instantiate a buffer
        let mut buffer = vec![];
        // Store if our value is negative
        let is_negative = value < 0;
        // Loop until we have a non-zero value
        while abs_value != 0 {
            buffer.push((abs_value & 0xff) as u8);
            abs_value >>= 8;
        }
        // Temporary reference to buffers length
        let len = buffer.len();
        // We already know at this point that the value is not zero, so this means we have an
        // element in the buffer. And we want to check if the first element is our marker for a
        // negative value
        if buffer[len - 1] & 0x80 != 0 {
            if is_negative {
                buffer.push(0x80);
            } else {
                buffer.push(0);
            }
        } else if is_negative {
            buffer[len - 1] |= 0x80;
        }

        Self { data: buffer }
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


#[cfg(test)]
mod tests {
    use crate::script::{Command, Element, Stack, op::op_dup};

    #[test]
    fn test_op_dup() {
        let mut stack = Stack::new();
        let elem1 = Element::from_vec(vec![1, 2, 3, 4]);
        let elem2 = Element::from_vec(vec![5, 6, 7, 8]);
        stack.push(elem1);
        stack.push(elem2.clone());
        assert!(op_dup(&mut stack) == true);

        for _idx in 0..2 {
            assert!(stack.pop().unwrap() == elem2);
        }
    }

    #[test]
    fn test_numeric_to_element() {
        let value = -128942432;
        let elem = Element::from_integer(value);
        assert!(elem == Element { data: [0x60, 0x81, 0xaf, 0x87].to_vec() } )
    }
}
