use std::error::Error;
use std::fmt::Debug;
use std::{
    any::type_name,
    collections::{linked_list::CursorMut, LinkedList},
    fmt::{self, Display},
    io::{Cursor, Read},
    iter,
};

use enum_as_inner::EnumAsInner;
use ethereum_types::U256;
use keccak_hash::H256;
use log::trace;
use mpt_trie::nibbles::{FromHexPrefixError, Nibbles};
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::{
    compact_mpt_processing::{AccountNodeData, ProcessedCompactOutput},
    compact_smt_processing::SmtNodeType,
    compact_to_mpt_trie::UnexpectedCompactNodeType,
};
use crate::{decoding::TrieType, trace_protocol::MptTrieCompact, types::TrieRootHash};

pub(super) type BranchMask = u32;

pub(super) type Balance = U256;
pub(super) type Nonce = U256;
pub(super) type HasCode = bool;
pub(super) type HasStorage = bool;

pub(super) type NodeType = u8;
pub(super) type Address = Vec<u8>;
pub(super) type Slot = Vec<u8>;
pub(super) type Value = Vec<u8>;

pub(super) type HashValue = H256;
pub(super) type RawValue = Vec<u8>;
pub(super) type RawCode = Vec<u8>;

pub(super) const MAX_WITNESS_ENTRIES_NEEDED_TO_MATCH_A_RULE: usize = 3;
pub(super) const BRANCH_MAX_CHILDREN: usize = 16;
pub(super) const CURSOR_ERROR_BYTES_MAX_LEN: usize = 10;

/// Result alias for any error that can occur when processing encoded compact
/// prestate.
pub type CompactParsingResult<T> = Result<T, CompactParsingError>;

/// An error from processing Erigon's compact witness format.
#[derive(Debug, Error)]
pub enum CompactParsingError {
    /// The header in the compact payload was missing. This is just a single
    /// byte that is used for versioning.
    #[error("Missing header")]
    MissingHeader,

    /// Encountered a byte representing an opcode that does not represent any
    /// known opcode
    #[error("Invalid opcode operator (\"{0:x}\")")]
    InvalidOpcode(u8),

    /// Encountered the end of the byte stream when we were still expecting more
    /// data.
    #[error("Reached the end of the byte stream when we still expected more data")]
    UnexpectedEndOfStream,

    /// Failed to decode a byte vector from CBOR.
    #[error("Unable to parse an expected byte vector (field name: {0}) (error: {1}). Cursor error info: {2}")]
    InvalidByteVector(&'static str, String, CursorBytesErrorInfo),

    /// Failed to decode a given type from CBOR.
    #[error(
        "Unable to parse the type \"{0}\" (field name: {1}) from bytes {2}. Cursor error info: {3} (err: {4})"
    )]
    InvalidBytesForType(
        &'static str,
        &'static str,
        String,
        CursorBytesErrorInfo,
        String,
    ),

    /// Encountered a sequence of instructions of nodes that should not be able
    /// to occur.
    #[error("Invalid block witness entries: {0:?}")]
    InvalidWitnessFormat(Vec<WitnessEntry>),

    /// Multiple entries were remaining after we were unable to apply any more
    /// rules. There should always only be one remaining entry after we can not
    /// apply any more rules.
    #[error("There were multiple entries remaining after the compact block witness was processed (Remaining entries: {0:#?})")]
    NonSingleEntryAfterProcessing(WitnessEntries),

    /// A branch was found that had an unexpected number of child nodes trailing
    /// it than expected.
    #[error("Branch mask {0:#b} stated there should be {1} preceding nodes but instead found {2} (nodes: {3:?})")]
    IncorrectNumberOfNodesPrecedingBranch(BranchMask, usize, usize, Vec<WitnessEntry>),

    /// Found a branch that had claimed to have `n` children but instead had a
    /// different amount.
    #[error(
        "Expected a branch to have {0} preceding nodes but only had {1} (mask: {2}, nodes: {3:?})"
    )]
    MissingExpectedNodesPrecedingBranch(usize, usize, BranchMask, Vec<WitnessEntry>),

    /// Expected a preceding node to be of a given type but instead found one of
    /// a different type.
    #[error("Expected the entry preceding {0} positions behind a {1} entry to be a node of type but instead found a {2} node. (nodes: {3:?})")]
    UnexpectedPrecedingNodeFoundWhenProcessingRule(usize, &'static str, String, Vec<WitnessEntry>),

    /// Expected a compact node type that should not be present in the given
    /// type of trie.
    #[error("Found an unexpected compact node type ({0:?}) during processing compact into a `mpt_trie` {1} partial trie.")]
    UnexpectedNodeForTrieType(UnexpectedCompactNodeType, TrieType),

    // TODO: No constructors for this, but I think there should be one in
    // [`key_bytes_to_nibbles`]...
    /// Error when constructing a key from bytes.
    #[error("Unable to create key nibbles from bytes {0}")]
    KeyError(#[from] FromHexPrefixError),
}

#[derive(Debug)]
pub(super) struct CursorBytesErrorInfo {
    error_start_pos: usize,
    bad_bytes_hex: String,
}

impl CursorBytesErrorInfo {
    pub(super) fn new(cursor: &Cursor<Vec<u8>>, error_start_pos: u64) -> Self {
        let mut cursor_cloned = cursor.clone();

        cursor_cloned.set_position(error_start_pos);
        let mut buf = vec![0; CURSOR_ERROR_BYTES_MAX_LEN];
        let num_bytes_read = cursor_cloned.read(&mut buf).unwrap();
        buf.truncate(num_bytes_read);

        let bad_bytes_hex = hex::encode(buf);

        Self {
            error_start_pos: error_start_pos as usize,
            bad_bytes_hex,
        }
    }
}

impl Display for CursorBytesErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Error byte position: {}, bad bytes hex ({} bytes following bad bytes): {}",
            self.error_start_pos, CURSOR_ERROR_BYTES_MAX_LEN, self.bad_bytes_hex
        )
    }
}

#[derive(Debug, enumn::N)]
pub(super) enum Opcode {
    Leaf = 0x00,
    Extension = 0x01,
    Branch = 0x02,
    Hash = 0x03,
    Code = 0x04,
    AccountLeaf = 0x05,
    EmptyRoot = 0x06,
    SMTLeaf = 0x07,
}

#[derive(Clone, Debug, EnumAsInner)]
pub(super) enum WitnessEntry {
    Instruction(Instruction),
    Node(NodeEntry),
}

impl Display for WitnessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessEntry::Instruction(i) => write!(f, "Instruction({})", i),
            WitnessEntry::Node(n) => write!(f, "Node({})", n),
        }
    }
}

// TODO: Ignore `NEW_TRIE` for now...
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Instruction {
    Leaf(Nibbles, RawValue),
    Extension(Nibbles),
    Branch(BranchMask),
    Hash(HashValue),
    Code(RawCode),
    AccountLeaf(Nibbles, Nonce, Balance, HasCode, HasStorage),
    EmptyRoot,
    SMTLeaf(NodeType, Address, Slot, Value),
}

impl Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Leaf(_, _) => write!(f, "Leaf"),
            Instruction::Extension(_) => write!(f, "Extension"),
            Instruction::Branch(_) => write!(f, "Branch"),
            Instruction::Hash(_) => write!(f, "Hash"),
            Instruction::Code(_) => write!(f, "Code"),
            Instruction::AccountLeaf(_, _, _, _, _) => write!(f, "AccountLeaf"),
            Instruction::EmptyRoot => write!(f, "EmptyRoot"),
            Instruction::SMTLeaf(_, _, _, _) => write!(f, "SMTLeaf"),
        }
    }
}

impl From<NodeEntry> for WitnessEntry {
    fn from(v: NodeEntry) -> Self {
        WitnessEntry::Node(v)
    }
}

impl From<Instruction> for WitnessEntry {
    fn from(v: Instruction) -> Self {
        Self::Instruction(v)
    }
}

// TODO: It's probably better to use two separate types for both mpt and smt
// nodes. Not urgent, but this is probably best for QoL...
#[derive(Clone, Debug, PartialEq)]
pub(super) enum NodeEntry {
    Branch([Option<Box<NodeEntry>>; 16]),
    BranchSMT([Option<Box<NodeEntry>>; 2]),
    Code(Vec<u8>),
    Empty,
    Hash(HashValue),
    Leaf(Nibbles, LeafNodeData),
    Extension(Nibbles, Box<NodeEntry>),
    SMTLeaf(SmtNodeType, Address, Slot, Value),
}

impl Display for NodeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeEntry::Branch(_) => write!(f, "Branch"),
            NodeEntry::BranchSMT(_) => write!(f, "BranchSMT"),
            NodeEntry::Code(_) => write!(f, "Code"),
            NodeEntry::Empty => write!(f, "Empty"),
            NodeEntry::Hash(_) => write!(f, "Hash"),
            NodeEntry::Leaf(_, _) => write!(f, "Leaf"),
            NodeEntry::Extension(_, _) => write!(f, "Extension"),
            NodeEntry::SMTLeaf(_, _, _, _) => write!(f, "SMTLeaf"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ValueNodeData(pub(super) Vec<u8>);

impl From<Vec<u8>> for ValueNodeData {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum LeafNodeData {
    Value(ValueNodeData),
    Account(AccountNodeData),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum AccountNodeCode {
    CodeNode(Vec<u8>),
    HashNode(TrieRootHash),
}

impl From<Vec<u8>> for AccountNodeCode {
    fn from(v: Vec<u8>) -> Self {
        Self::CodeNode(v)
    }
}

impl From<TrieRootHash> for AccountNodeCode {
    fn from(v: TrieRootHash) -> Self {
        Self::HashNode(v)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct SMTLeafNode {
    pub(super) address: Vec<u8>,
    pub(super) storage_key: Vec<u8>,
    pub(super) value: Vec<u8>,
}

impl SMTLeafNode {
    fn new(address: Vec<u8>, storage_key: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            address,
            storage_key,
            value,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Header {
    pub(super) version: u8,
}

impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Erigon block witness version {}", self.version)
    }
}

impl Header {
    pub(crate) fn version_is_compatible(&self, target_ver: u8) -> bool {
        self.version == target_ver
    }
}

#[derive(Debug)]
pub(super) struct ParserState {
    pub(super) entries: WitnessEntries,
}

struct Stack<T> {
    stack: Vec<T>,
}

impl<T> Stack<T> {
    fn new() -> Self {
        Stack { stack: Vec::new() }
    }

    fn length(&self) -> usize {
        self.stack.len()
    }

    fn pop(&mut self) -> Option<T> {
        self.stack.pop()
    }

    fn push(&mut self, item: T) {
        self.stack.push(item)
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    fn peek(&self) -> Option<&T> {
        self.stack.last()
    }
}

pub(super) trait CompactCursor {
    fn new(bytes: Vec<u8>) -> Self;
    fn intern(&mut self) -> &mut Cursor<Vec<u8>>;
    fn read_t<T: DeserializeOwned>(&mut self, field_name: &'static str) -> CompactParsingResult<T>;
    fn read_byte(&mut self) -> CompactParsingResult<u8>;
    fn read_cbor_byte_array_to_vec(
        &mut self,
        field_name: &'static str,
    ) -> CompactParsingResult<Vec<u8>>;
    fn read_cbor_u256(&mut self, field_name: &'static str) -> CompactParsingResult<U256>;
    fn read_non_cbor_h256(&mut self, field_name: &'static str) -> CompactParsingResult<H256>;
    fn at_eof(&self) -> bool;
}

#[derive(Debug)]
pub(super) struct CompactCursorFast {
    intern: Cursor<Vec<u8>>,
}

impl CompactCursor for CompactCursorFast {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            intern: Cursor::new(bytes),
        }
    }

    fn intern(&mut self) -> &mut Cursor<Vec<u8>> {
        &mut self.intern
    }

    fn read_t<T: DeserializeOwned>(&mut self, field_name: &'static str) -> CompactParsingResult<T> {
        let starting_pos = self.intern.position();

        ciborium::from_reader(&mut self.intern).map_err(move |err| {
            let ending_pos = self.intern.position();
            let type_bytes = self.intern.clone().into_inner()
                [starting_pos as usize..ending_pos as usize]
                .to_vec();
            let type_bytes_hex = hex::encode(type_bytes);

            let cursor_err_info = CursorBytesErrorInfo::new(&self.intern, starting_pos);

            CompactParsingError::InvalidBytesForType(
                type_name::<T>(),
                field_name,
                type_bytes_hex,
                cursor_err_info,
                err.to_string(),
            )
        })
    }

    fn read_byte(&mut self) -> CompactParsingResult<u8> {
        let mut single_byte_buf = [0];

        // Assume this is always caused by hitting the end of the stream?
        self.intern
            .read_exact(&mut single_byte_buf)
            .map_err(|_err| CompactParsingError::UnexpectedEndOfStream)?;

        Ok(single_byte_buf[0])
    }

    // I don't think it's possible to not read to a vec here with `ciborium`... In
    // theory this should be doable, but the way the library I don't think we can.
    fn read_cbor_byte_array_to_vec(
        &mut self,
        field_name: &'static str,
    ) -> CompactParsingResult<Vec<u8>> {
        let cursor_start_pos = self.intern.position();

        Self::ciborium_byte_vec_err_reader_res_to_parsing_res(
            ciborium::from_reader(&mut self.intern),
            cursor_start_pos,
            &mut self.intern,
            field_name,
        )
    }

    // TODO: Clean up code duplication...
    fn read_cbor_u256(&mut self, field_name: &'static str) -> CompactParsingResult<U256> {
        let b_array = self.read_cbor_byte_array_to_vec(field_name)?;
        Ok(U256::from_big_endian(&b_array))
    }

    fn read_non_cbor_h256(&mut self, field_name: &'static str) -> CompactParsingResult<H256> {
        let cursor_start_pos = self.intern().position();
        let mut h256_bytes = [0; 32];

        self.intern.read_exact(&mut h256_bytes).map_err(|err| {
            let hex_bytes = hex::encode(h256_bytes);
            let cursor_err_info = CursorBytesErrorInfo::new(self.intern(), cursor_start_pos);
            CompactParsingError::InvalidBytesForType(
                type_name::<H256>(),
                field_name,
                hex_bytes,
                cursor_err_info,
                err.to_string(),
            )
        })?;

        Ok(H256(h256_bytes))
    }

    fn at_eof(&self) -> bool {
        self.intern.position() as usize == self.intern.get_ref().len()
    }
}

impl CompactCursorFast {
    // TODO: Keep around until we decide if we want to attempt the non-vec
    // allocating route...
    fn ciborium_byte_vec_err_reader_res_to_parsing_res<T, E: Error>(
        res: Result<T, E>,
        cursor_start_pos: u64,
        cursor: &mut Cursor<Vec<u8>>,
        field_name: &'static str,
    ) -> CompactParsingResult<T> {
        res.map_err(|err| {
            let cursor_err_info = CursorBytesErrorInfo::new(cursor, cursor_start_pos);
            CompactParsingError::InvalidByteVector(field_name, err.to_string(), cursor_err_info)
        })
    }
}

#[derive(Debug)]
pub(super) struct DebugCompactCursor(CompactCursorFast);

// TODO: There are some decent opportunities to reduce code duplication here...
impl CompactCursor for DebugCompactCursor {
    fn new(bytes: Vec<u8>) -> Self {
        Self(CompactCursorFast::new(bytes))
    }

    fn intern(&mut self) -> &mut Cursor<Vec<u8>> {
        self.0.intern()
    }

    fn read_t<T: DeserializeOwned>(&mut self, field_name: &'static str) -> CompactParsingResult<T> {
        let cursor_start_pos = self.0.intern.position();
        let res = self.0.read_t(field_name);

        if res.is_ok() {
            let info_payload = get_bytes_and_debug_info_from_cursor(self, cursor_start_pos);
            trace!("`read_t` successfully parsed \"{}\" from bytes \"{}\" at byte position \"{}\" (hex start position: \"{}\")", field_name, info_payload.bytes_hex, cursor_start_pos, info_payload.hex_start_pos);
        }

        res
    }

    fn read_byte(&mut self) -> CompactParsingResult<u8> {
        let res = self.0.read_byte();

        if let Ok(byte) = res.as_ref() {
            trace!("`read_byte` successfully parsed \"{}\"", byte);
        }

        res
    }

    fn read_cbor_byte_array_to_vec(
        &mut self,
        field_name: &'static str,
    ) -> CompactParsingResult<Vec<u8>> {
        let cursor_start_pos = self.0.intern.position();
        let res = self.0.read_cbor_byte_array_to_vec(field_name);

        if let Ok(bytes) = res.as_ref() {
            let hex_bytes = hex::encode(bytes);
            let hex_start_pos = cursor_start_pos * 2;
            trace!("`read_cbor_byte_array_to_vec` successfully parsed \"{}\" into a byte array at position \"{}\" (hex start position: \"{}\")", hex_bytes, cursor_start_pos, hex_start_pos);
        }

        res
    }

    fn read_cbor_u256(&mut self, field_name: &'static str) -> CompactParsingResult<U256> {
        let cursor_start_pos = self.0.intern.position();
        let res = self.0.read_cbor_u256(field_name);

        if let Ok(v) = res.as_ref() {
            let hex_bytes = format!("{:x}", v);
            let hex_start_pos = cursor_start_pos * 2;
            trace!("`read_cbor_u256` successfully parsed \"{}\" (hex bytes: {}) into an U256 at position \"{}\" (hex start position: \"{}\")", v, hex_bytes, cursor_start_pos, hex_start_pos);
        }

        res
    }

    fn read_non_cbor_h256(&mut self, field_name: &'static str) -> CompactParsingResult<H256> {
        let cursor_start_pos = self.0.intern.position();
        let res = self.0.read_non_cbor_h256(field_name);

        if let Ok(v) = res.as_ref() {
            // Need to use hex formatting otherwise the default display formatting truncates
            // it.
            let v_full_readable = format!("{:x}", v);
            let hex_bytes = hex::encode(get_bytes_from_cursor(self, cursor_start_pos));
            let hex_start_pos = cursor_start_pos * 2;

            trace!("`read_non_cbor_h256` successfully parsed \"{}\" (hex bytes: {}) into an H256 at position \"{}\" (hex start position: \"{}\")", v_full_readable, hex_bytes, cursor_start_pos, hex_start_pos);
        }

        res
    }

    fn at_eof(&self) -> bool {
        let res = self.0.at_eof();

        if res {
            trace!("`at_eof` returned \"true\" for initial byte payload");
        }

        res
    }
}

pub(super) fn get_bytes_from_cursor<C: CompactCursor>(
    cursor: &mut C,
    cursor_start_pos: u64,
) -> Vec<u8> {
    let cursor_end_pos = cursor.intern().position();
    let mut cloned_cursor = cursor.intern().clone();

    // Rewind the cursor.
    cloned_cursor.set_position(cursor_start_pos);

    let num_bytes_read = (cursor_end_pos - cursor_start_pos) as usize;
    let mut t_bytes = vec![0; num_bytes_read];
    cloned_cursor.read_exact(&mut t_bytes).unwrap();

    t_bytes
}

pub(super) struct WitnessBytes<C: CompactCursor> {
    pub(super) byte_cursor: C,
    pub(super) instrs: WitnessEntries,
}

impl<C: CompactCursor> WitnessBytes<C> {
    pub(super) fn new(witness_bytes: Vec<u8>) -> Self {
        Self {
            byte_cursor: C::new(witness_bytes),
            instrs: WitnessEntries::default(),
        }
    }

    pub(super) fn process_operator(&mut self) -> CompactParsingResult<()> {
        let opcode_byte = self.byte_cursor.read_byte()?;
        println!("------------ opcode byte: {}", opcode_byte);

        let opcode: Opcode =
            Opcode::n(opcode_byte).ok_or(CompactParsingError::InvalidOpcode(opcode_byte))?;

        println!("Processed \"{:?}\" opcode", opcode);

        self.process_data_following_opcode(opcode)
    }

    fn process_data_following_opcode(&mut self, opcode: Opcode) -> CompactParsingResult<()> {
        match opcode {
            Opcode::Leaf => self.process_leaf(),
            Opcode::Extension => self.process_extension(),
            Opcode::Branch => self.process_branch(),
            Opcode::Hash => self.process_hash(),
            Opcode::Code => self.process_code(),
            Opcode::AccountLeaf => self.process_account_leaf(),
            Opcode::EmptyRoot => self.process_empty_root(),
            Opcode::SMTLeaf => self.process_smt_leaf(),
        }
    }

    pub(super) fn process_into_instructions_and_header(
        mut self,
    ) -> CompactParsingResult<(Header, WitnessEntries)> {
        let header = self.parse_header()?;

        loop {
            if self.byte_cursor.at_eof() {
                break;
            }

            self.process_operator()?;
        }

        Ok((header, self.instrs))
    }

    pub(super) fn process_leaf(&mut self) -> CompactParsingResult<()> {
        println!("-------------- leaf");
        let key = key_bytes_to_nibbles(&self.byte_cursor.read_cbor_byte_array_to_vec("leaf key")?);
        let value_raw = self.byte_cursor.read_cbor_byte_array_to_vec("leaf value")?;

        self.push_entry(Instruction::Leaf(key, value_raw));
        Ok(())
    }

    pub(super) fn process_extension(&mut self) -> CompactParsingResult<()> {
        println!("-------------- extension");
        let key = key_bytes_to_nibbles(
            &self
                .byte_cursor
                .read_cbor_byte_array_to_vec("extension key")?,
        );

        self.push_entry(Instruction::Extension(key));
        Ok(())
    }

    pub(super) fn process_branch(&mut self) -> CompactParsingResult<()> {
        println!("-------------- branch");
        let mask = self.byte_cursor.read_t("mask")?;
        println!("Processed \"{:?}\" mask", mask);

        self.push_entry(Instruction::Branch(mask));
        Ok(())
    }

    pub(super) fn process_hash(&mut self) -> CompactParsingResult<()> {
        println!("-------------- hash");
        let hash = self.byte_cursor.read_non_cbor_h256("hash")?;

        self.push_entry(Instruction::Hash(hash));
        Ok(())
    }

    pub(super) fn process_code(&mut self) -> CompactParsingResult<()> {
        println!("-------------- code");
        let code = self.byte_cursor.read_t("code")?;

        self.push_entry(Instruction::Code(code));
        Ok(())
    }

    pub(super) fn process_account_leaf(&mut self) -> CompactParsingResult<()> {
        println!("-------------- account leaf");
        let key = key_bytes_to_nibbles(
            &self
                .byte_cursor
                .read_cbor_byte_array_to_vec("account leaf key")?,
        );
        let flags: AccountLeafFlags = self.byte_cursor.read_byte()?.into();
        let nonce: U256 =
            Self::read_account_flag_field_if_present_or_default(flags.nonce_present, || {
                self.byte_cursor.read_t::<u64>("account leaf nonce")
            })?
            .into();

        let balance =
            Self::read_account_flag_field_if_present_or_default(flags.balance_present, || {
                self.byte_cursor.read_cbor_u256("account leaf balance")
            })?;

        // I don't think we need code size?
        let _ = Self::read_account_flag_field_if_present_or_default(flags.code_present, || {
            self.byte_cursor.read_t::<u64>("code size")
        })?;

        // TODO: process actual storage trie probably? Wait until we know what is going
        // on here.

        self.push_entry(Instruction::AccountLeaf(
            key,
            nonce,
            balance,
            flags.code_present,
            flags.storage_present,
        ));

        Ok(())
    }

    fn read_account_flag_field_if_present_or_default<F, T>(
        present_flag: bool,
        mut read_f: F,
    ) -> CompactParsingResult<T>
    where
        F: FnMut() -> CompactParsingResult<T>,
        T: Default,
    {
        Ok(match present_flag {
            false => T::default(),
            true => (read_f)()?,
        })
    }

    pub(super) fn process_empty_root(&mut self) -> CompactParsingResult<()> {
        self.push_entry(Instruction::EmptyRoot);
        Ok(())
    }

    fn push_entry(&mut self, instr: Instruction) {
        self.instrs.push(instr.into())
    }

    pub(super) fn parse_header(&mut self) -> CompactParsingResult<Header> {
        let h_byte = self
            .byte_cursor
            .read_byte()
            .map_err(|_| CompactParsingError::MissingHeader)?;

        Ok(Header { version: h_byte })
    }

    pub(super) fn process_smt_leaf(&mut self) -> CompactParsingResult<()> {
        let node_type: u8 = self.byte_cursor.read_t("nodeType")?;
        println!("-------------- smt leaf, node_type {:?}", node_type);
        let address: Vec<u8> = self.byte_cursor.read_cbor_byte_array_to_vec("address")?;
        let mut storage = Vec::new();
        if node_type == 0x03 {
            storage = self.byte_cursor.read_cbor_byte_array_to_vec("storage")?;
        }
        let value = self.byte_cursor.read_cbor_byte_array_to_vec("value")?;
        self.push_entry(Instruction::SMTLeaf(node_type, address, storage, value));
        Ok(())
    }
}

pub(super) struct CursorBytesDebugInfo {
    bytes_hex: String,
    hex_start_pos: usize,
}

pub(super) fn get_bytes_and_debug_info_from_cursor<C: CompactCursor>(
    cursor: &mut C,
    cursor_start_pos: u64,
) -> CursorBytesDebugInfo {
    let bytes = get_bytes_from_cursor(cursor, cursor_start_pos);

    let bytes_hex = hex::encode(bytes);
    let hex_start_pos = cursor_start_pos as usize * 2;

    CursorBytesDebugInfo {
        bytes_hex,
        hex_start_pos,
    }
}

// TODO: This could probably be made a bit faster...
pub(super) fn key_bytes_to_nibbles(bytes: &[u8]) -> Nibbles {
    let mut key = Nibbles::default();

    if bytes.is_empty() {
        return key;
    }

    // I have no idea why Erigon is doing this with their keys, as I'm don't think
    // this is part of the yellow paper at all?
    if bytes.len() == 1 {
        let low_nib = bytes[0] & 0b00001111;
        key.push_nibble_back(low_nib);
    }

    let flags = bytes[0];
    let is_odd = (flags & 0b00000001) != 0;
    let has_term = (flags & 0b00000010) != 0;

    // ... Term bit seems to have no effect on the key?
    let actual_key_bytes = match has_term {
        false => &bytes[1..],
        true => &bytes[1..],
    };

    if actual_key_bytes.is_empty() {
        return key;
    }

    let final_byte_idx = actual_key_bytes.len() - 1;

    // The compact key format is kind of weird. We need to read the nibbles
    // backwards from how we expect it internally.
    for byte in &actual_key_bytes[..(final_byte_idx)] {
        let high_nib = (byte & 0b11110000) >> 4;
        let low_nib = byte & 0b00001111;

        key.push_nibble_back(high_nib);
        key.push_nibble_back(low_nib);
    }

    // The final byte we might need to ignore the last nibble, so we need to do it
    // separately.
    let final_byte = actual_key_bytes[final_byte_idx];
    let high_nib = (final_byte & 0b11110000) >> 4;
    key.push_nibble_back(high_nib);

    if !is_odd {
        let low_nib = final_byte & 0b00001111;
        key.push_nibble_back(low_nib);
    }

    key
}

#[derive(Debug)]
struct AccountLeafFlags {
    code_present: bool,
    storage_present: bool,
    nonce_present: bool,
    balance_present: bool,
}

impl From<u8> for AccountLeafFlags {
    fn from(v: u8) -> Self {
        Self {
            code_present: v & 0b0001 != 0,
            storage_present: v & 0b0010 != 0,
            nonce_present: v & 0b0100 != 0,
            balance_present: v & 0b1000 != 0,
        }
    }
}

/// We kind of want a wrapper around the actual data structure I think since
/// there's a good chance this will change a few times in the future.
#[derive(Debug, Default)]
pub struct WitnessEntries {
    // Yeah a LL is actually (unfortunately) a very good choice here. We will be doing a ton of
    // inserts mid-list, and the list can get very large. There might be a better choice for a data
    // structure, but for now, this will make performance not scale exponentially with list
    // size.
    pub(super) intern: LinkedList<WitnessEntry>,
}

impl WitnessEntries {
    pub(super) fn push(&mut self, entry: WitnessEntry) {
        self.intern.push_back(entry)
    }

    pub(super) fn pop(&mut self) -> Option<WitnessEntry> {
        self.intern.pop_back()
    }

    pub(super) fn create_collapsable_traverser(&mut self) -> CollapsableWitnessEntryTraverser {
        let entry_cursor = self.intern.cursor_front_mut();

        CollapsableWitnessEntryTraverser { entry_cursor }
    }

    pub(super) fn len(&self) -> usize {
        self.intern.len()
    }
}

// It's not quite an iterator, so this is the next best name that I can come up
// with.
#[derive(Debug)]
pub(super) struct CollapsableWitnessEntryTraverser<'a> {
    entry_cursor: CursorMut<'a, WitnessEntry>,
}

// TODO: For now, lets just use pure values in the buffer, but we probably want
// to switch over to references later...
impl<'a> CollapsableWitnessEntryTraverser<'a> {
    pub(super) fn advance(&mut self) {
        self.entry_cursor.move_next();
    }

    pub(super) fn get_next_n_elems(&self, n: usize) -> impl Iterator<Item = &WitnessEntry> {
        let mut read_only_cursor = self.entry_cursor.as_cursor();

        iter::from_fn(move || {
            // Index returns a `None` if we are at the end of the LL.
            read_only_cursor.index().map(|_| {
                let entry = read_only_cursor.current();
                read_only_cursor.move_next();
                entry
            })
        })
        .flatten()
        .take(n)
    }

    pub(super) fn get_prev_n_elems(&self, n: usize) -> impl Iterator<Item = &WitnessEntry> {
        let mut read_only_cursor = self.entry_cursor.as_cursor();

        iter::from_fn(move || {
            read_only_cursor.index().map(|_| {
                read_only_cursor.move_prev();
                read_only_cursor.current()
            })
        })
        .flatten()
        .take(n)
    }

    /// Get the previous `n` elements into a buf. Note that this does not
    /// include the element that we are currently pointing to.
    pub(super) fn get_prev_n_elems_into_buf(&self, n: usize, buf: &mut Vec<WitnessEntry>) {
        buf.clear();
        buf.extend(self.get_prev_n_elems(n).cloned())
    }

    /// Get the next `n` elements into a buf. Note that this includes the
    /// element that we are currently pointing to.
    pub(super) fn get_next_n_elems_into_buf(&self, n: usize, buf: &mut Vec<WitnessEntry>) {
        buf.clear();
        buf.extend(self.get_next_n_elems(n).cloned());
    }

    // Inclusive.
    pub(super) fn replace_next_n_entries_with_single_entry(
        &mut self,
        n: usize,
        entry: WitnessEntry,
    ) {
        for _ in 0..n {
            self.entry_cursor.remove_current();
        }

        self.entry_cursor.insert_after(entry)
    }

    // Inclusive.
    pub(super) fn replace_prev_n_entries_with_single_entry(
        &mut self,
        n: usize,
        entry: WitnessEntry,
    ) {
        for _ in 0..n {
            self.entry_cursor.remove_current();
            self.entry_cursor.move_prev();

            if self.entry_cursor.index().is_none() {
                break;
            }
        }
        self.entry_cursor.insert_after(entry);

        self.entry_cursor.move_next();
    }

    pub(super) fn at_end(&self) -> bool {
        self.entry_cursor.as_cursor().current().is_none()
    }
}

pub(super) fn try_get_node_entry_from_witness_entry(entry: &WitnessEntry) -> Option<&NodeEntry> {
    match entry {
        WitnessEntry::Node(n_entry) => Some(n_entry),
        _ => None,
    }
}

#[derive(Debug)]
pub(super) enum TraverserDirection {
    Forwards,
    Backwards,
    Both,
}

pub(super) fn process_compact_prestate_common<T>(
    state_bytes: Vec<u8>,
    create_and_extract_header_f: fn(Vec<u8>) -> CompactParsingResult<(Header, ParserState)>,
    parse_f: fn(ParserState) -> CompactParsingResult<T>,
) -> CompactParsingResult<ProcessedCompactOutput<T>>
where
    T: Debug,
{
    let (header, mut parser) = create_and_extract_header_f(state_bytes)?;
    println!("-------------- header: {:?}", header);
    let witness_out = (parse_f(parser))?;
    println!("-------------- witness_out: {:?}", witness_out);

    let out = ProcessedCompactOutput {
        header,
        witness_out,
    };

    Ok(out)
}

#[cfg(test)]
mod tests {
    use mpt_trie::{nibbles::Nibbles, partial_trie::PartialTrie};

    use super::Instruction;
    use crate::compact::{
        compact_debug_tools::parse_just_to_instructions,
        compact_mpt_processing::process_compact_mpt_prestate_debug,
        compact_processing_common::{key_bytes_to_nibbles, ParserState},
        complex_test_payloads::{
            TEST_PAYLOAD_1, TEST_PAYLOAD_10, TEST_PAYLOAD_2, TEST_PAYLOAD_3, TEST_PAYLOAD_4,
            TEST_PAYLOAD_5, TEST_PAYLOAD_6, TEST_PAYLOAD_7, TEST_PAYLOAD_8, TEST_PAYLOAD_9,
        },
    };

    const SIMPLE_PAYLOAD_STR: &str = "01004110443132333400411044313233340218300042035044313233350218180158200000000000000000000000000000000000000000000000000000000000000012";

    fn init() {
        let _ = pretty_env_logger::try_init();
    }

    fn h_decode_key(h_bytes: &str) -> Nibbles {
        let bytes = hex::decode(h_bytes).unwrap();
        key_bytes_to_nibbles(&bytes)
    }

    fn h_decode(b_str: &str) -> Vec<u8> {
        hex::decode(b_str).unwrap()
    }

    #[test]
    fn simple_instructions_are_parsed_correctly() {
        init();

        let bytes = hex::decode(SIMPLE_PAYLOAD_STR).unwrap();
        let instrs = parse_just_to_instructions(bytes);

        let instrs = match instrs {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };

        let expected_instrs = vec![
            Instruction::Leaf(h_decode_key("10"), h_decode("31323334")),
            Instruction::Leaf(h_decode_key("10"), h_decode("31323334")),
            Instruction::Branch(0b00110000),
            Instruction::Leaf(h_decode_key("0350"), h_decode("31323335")),
            Instruction::Branch(0b00011000),
            Instruction::Extension(h_decode_key(
                "0000000000000000000000000000000000000000000000000000000000000012",
            )),
        ];

        for (i, expected_instr) in expected_instrs.into_iter().enumerate() {
            assert_eq!(expected_instr, instrs[i])
        }
    }

    #[test]
    fn complex_payload_1() {
        init();
        TEST_PAYLOAD_1.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_2() {
        init();
        TEST_PAYLOAD_2.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_3() {
        init();
        TEST_PAYLOAD_3.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_4() {
        init();
        TEST_PAYLOAD_4.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_5() {
        init();
        TEST_PAYLOAD_5.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_6() {
        init();
        TEST_PAYLOAD_6.parse_and_check_hash_matches_with_debug();
    }

    #[test]
    fn complex_payload_7() {
        init();
        TEST_PAYLOAD_7.parse_and_check_hash_matches_with_debug_smt();
    }

    #[test]
    fn complex_payload_8() {
        init();
        TEST_PAYLOAD_8.parse_and_check_hash_matches_with_debug_smt();
    }

    #[test]
    fn complex_payload_9() {
        init();
        TEST_PAYLOAD_9.parse_and_check_hash_matches_with_debug_smt();
    }

    #[test]
    fn complex_payload_10() {
        init();
        TEST_PAYLOAD_10.parse_and_check_hash_matches_with_debug_smt();
    }
}
