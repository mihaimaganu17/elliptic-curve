//! Module for defining the bitcoin's Script opcodes and their respective operation implementation
use crate::script::{Stack, Element};

/// Opcodes process the data. They consume 0 or more elements from the processing stack and push
/// zero or more elementes back to the stack.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Opcode {
    // Specifies the OP_DUP operation, which duplicates the top element of the stack
    Dup,
    Hash256,
    Hash160,
    EqualVerify,
    If,
    NotIf,
    ToAltStack,
    FromAltStack,
    CheckSig,
    CheckSigVerify,
    CheckMultiSig,
    CheckMultiSigVerify,
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
            Self::If => opcode::OP_IF,
            Self::NotIf => opcode::OP_NOTIF,
            Self::ToAltStack => opcode::OP_TOALTSTACK,
            Self::FromAltStack => opcode::OP_FROMALTSTACK,
            Self::CheckSig => opcode::OP_CHECKSIG,
            Self::CheckSigVerify => opcode::OP_CHECKSIGVERIFY,
            Self::CheckMultiSig => opcode::OP_CHECKMULTISIG,
            Self::CheckMultiSigVerify => opcode::OP_CHECKMULTISIGVERIFY,
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
            opcode::OP_IF => Self::If,
            opcode::OP_NOTIF => Self::NotIf,
            opcode::OP_TOALTSTACK => Self::ToAltStack,
            opcode::OP_FROMALTSTACK => Self::FromAltStack,
            opcode::OP_CHECKSIG => Self::CheckSig,
            opcode::OP_CHECKSIGVERIFY => Self::CheckSigVerify,
            opcode::OP_CHECKMULTISIG => Self::CheckMultiSig,
            opcode::OP_CHECKMULTISIGVERIFY => Self::CheckMultiSigVerify,
            // If the operation is not yet supported, we just initialize a no op
            _ => {
                Self::Nop
            }
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
        if let Some(elem) = maybe_elem {
            let hashed_vec = crate::hashing::double_sha256(elem.as_ref());
            let hashed_elem_cmd = Element::from_vec(hashed_vec);
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
        if let Some(elem) = maybe_elem {
            let hashed_vec = crate::hashing::hash160(elem.as_ref());
            let hashed_elem = Element::from_vec(hashed_vec);
            stack.push(hashed_elem);
            true
        } else {
            false
        }
    }
}

// List of opcodes provided as constants that indicate what operation to perform
pub mod opcode {
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
    // Opcode for the `if` conditional
    pub const OP_IF: u8 = 0x63;
    // Opcode for the not `if` conditional
    pub const OP_NOTIF: u8 = 0x64;
    // Puts the input onto the top of the alt stack. Removes it from the main stack.
    pub const OP_TOALTSTACK: u8 = 0x6b;
    // Puts the input onto the top of the alt stack. Removes it from the main stack.
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    // Opcode duplicates the top element of the stack
    pub const OP_DUP: u8 = 0x76;
    // Same as `OP_EQUAL`, but runs `OP_VERIFY` afterward.
    pub const OP_EQUALVERIFY: u8 = 0x88;
    // Crypto functions
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    // Opcode for operation that verifies that a signature is valid
    pub const OP_CHECKSIG: u8 = 0xac;
    // Same as `OP_CHECKSIG`, but `OP_VERIFY` is executed afterward.
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    // Like `OP_CHEKSIG`, but for multiple signature, pubkey pairs
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    // Same as `OP_CHECKMULTISIG`, but `OP_VERIFY` is executed afterward.
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
}
