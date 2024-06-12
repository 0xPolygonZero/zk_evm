//! Processing for the compact format as specified here: <https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md>

use std::{
    any::type_name,
    collections::{linked_list::CursorMut, HashMap, LinkedList},
    error::Error,
    fmt::{self, Display},
    io::{Cursor, Read},
    iter,
};

use enum_as_inner::EnumAsInner;
use ethereum_types::{H256, U256};
use log::trace;
use mpt_trie::{
    nibbles::{FromHexPrefixError, Nibbles},
    partial_trie::HashedPartialTrie,
    trie_ops::TrieOpError,
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::compact_to_partial_trie::{
    create_partial_trie_from_remaining_witness_elem, create_storage_partial_trie_from_compact_node,
    StateTrieExtractionOutput, UnexpectedCompactNodeType,
};
use crate::{
    decoding::TrieType,
    trace_protocol::TrieCompact,
    types::{HashedAccountAddr, TrieRootHash},
};

/// Result alias for any error that can occur when processing encoded compact
/// prestate.
pub type CompactParsingResult<T> = Result<T, CompactParsingError>;

type BranchMask = u32;

type Balance = U256;
type Nonce = U256;
type HasCode = bool;
type HasStorage = bool;

type HashValue = H256;
type RawValue = Vec<u8>;
type RawCode = Vec<u8>;

const MAX_WITNESS_ENTRIES_NEEDED_TO_MATCH_A_RULE: usize = 3;
const BRANCH_MAX_CHILDREN: usize = 16;
const CURSOR_ERROR_BYTES_MAX_LEN: usize = 10;

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

    /// Failure due to an incompatible version.
    #[error("Incompatible version, expected one of: {0:?}, actual: {1}")]
    IncompatibleVersion(Vec<u8>, u8),

    /// Failure due to a trie operation error.
    #[error("Trie operation error: {0}")]
    TrieOpError(TrieOpError),
}

impl From<TrieOpError> for CompactParsingError {
    fn from(err: TrieOpError) -> Self {
        CompactParsingError::TrieOpError(err)
    }
}

/// Represents detailed error information about issues encountered
/// while processing byte streams with a cursor.
#[derive(Debug)]
pub struct CursorBytesErrorInfo {
    error_start_pos: usize,
    bad_bytes_hex: String,
}

impl CursorBytesErrorInfo {
    fn new(cursor: &Cursor<Vec<u8>>, error_start_pos: u64) -> Self {
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
enum Opcode {
    Leaf = 0x00,
    Extension = 0x01,
    Branch = 0x02,
    Hash = 0x03,
    Code = 0x04,
    AccountLeaf = 0x05,
    EmptyRoot = 0x06,
}

/// Compact witness entry.
#[derive(Clone, Debug, EnumAsInner)]
pub enum WitnessEntry {
    /// An instruction.
    Instruction(Instruction),
    /// A node.
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

/// A type alias for a list of witness entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Instruction {
    /// A leaf node.
    Leaf(Nibbles, RawValue),
    /// An extension node.
    Extension(Nibbles),
    /// A branch node.
    Branch(BranchMask),
    /// A hash node.
    Hash(HashValue),
    /// A code node.
    Code(RawCode),
    /// An account leaf node.
    AccountLeaf(Nibbles, Nonce, Balance, HasCode, HasStorage),
    /// An empty root node.
    EmptyRoot,
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

/// A node witness entry.
#[derive(Clone, Debug)]
pub enum NodeEntry {
    /// A branch node.
    Branch([Option<Box<NodeEntry>>; 16]),
    /// A code node.
    Code(Vec<u8>),
    /// An empty node.
    Empty,
    /// A hash node.
    Hash(HashValue),
    /// A leaf node.
    Leaf(Nibbles, LeafNodeData),
    /// An extension node.
    Extension(Nibbles, Box<NodeEntry>),
}

impl Display for NodeEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeEntry::Branch(_) => write!(f, "Branch"),
            NodeEntry::Code(_) => write!(f, "Code"),
            NodeEntry::Empty => write!(f, "Empty"),
            NodeEntry::Hash(_) => write!(f, "Hash"),
            NodeEntry::Leaf(_, _) => write!(f, "Leaf"),
            NodeEntry::Extension(_, _) => write!(f, "Extension"),
        }
    }
}

/// A value of a node data.
#[derive(Clone, Debug)]
pub struct ValueNodeData(pub(super) Vec<u8>);

impl From<Vec<u8>> for ValueNodeData {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

/// A leaf node data.
#[derive(Clone, Debug)]
pub enum LeafNodeData {
    /// A value node.
    Value(ValueNodeData),
    /// An account node.
    Account(AccountNodeData),
}

/// An account node code.
#[derive(Clone, Debug)]
pub enum AccountNodeCode {
    /// A code node.
    CodeNode(Vec<u8>),
    /// A hash node.
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

/// An account node data.
#[derive(Clone, Debug)]
pub struct AccountNodeData {
    /// The nonce of the account.
    pub nonce: Nonce,
    /// The balance of the account.
    pub balance: Balance,
    /// The storage trie of the account.
    pub storage_trie: Option<HashedPartialTrie>,
    /// The code of the account.
    pub account_node_code: Option<AccountNodeCode>,
}

impl AccountNodeData {
    const fn new(
        nonce: Nonce,
        balance: Balance,
        storage_trie: Option<HashedPartialTrie>,
        account_node_code: Option<AccountNodeCode>,
    ) -> Self {
        Self {
            nonce,
            balance,
            storage_trie,
            account_node_code,
        }
    }
}

/// A witness header.
#[derive(Debug)]
pub struct Header {
    /// The version of the witness.
    pub version: u8,
}

impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Erigon block witness version {}", self.version)
    }
}

impl Header {
    pub(crate) const fn version_is_compatible(&self, target_ver: u8) -> bool {
        self.version == target_ver
    }
}

// #[derive(Debug)]
// pub struct CompactWitnessDecodingOutput {
//     pub tries: PartialTriePreImages,
//     pub code: Option<HashMap<CodeHash, Vec<u8>>>,
// }

#[derive(Debug)]
struct ParserState {
    entries: WitnessEntries,
}

impl ParserState {
    fn create_and_extract_header(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::<CompactCursorFast>::new(witness_bytes_raw);
        let (header, entries) = witness_bytes.process_into_instructions_and_header()?;

        let p_state = Self { entries };

        Ok((header, p_state))
    }

    // TODO: Move behind a feature flag...
    fn create_and_extract_header_debug(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(witness_bytes_raw);
        let (header, entries) = witness_bytes.process_into_instructions_and_header()?;

        let p_state = Self { entries };

        Ok((header, p_state))
    }

    fn parse(mut self) -> CompactParsingResult<StateTrieExtractionOutput> {
        let mut entry_buf = Vec::new();

        loop {
            let num_rules_applied = self.apply_rules_to_witness_entries(&mut entry_buf)?;

            if num_rules_applied == 0 {
                break;
            }
        }

        let res = match self.entries.len() {
            1 => create_partial_trie_from_remaining_witness_elem(self.entries.pop().unwrap()),

            // Case for when nothing except the header is passed in.
            0 => Ok(StateTrieExtractionOutput::default()),
            _ => Err(CompactParsingError::NonSingleEntryAfterProcessing(
                self.entries,
            )),
        }?;

        Ok(res)
    }

    fn apply_rules_to_witness_entries(
        &mut self,
        entry_buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<usize> {
        let mut traverser = self.entries.create_collapsable_traverser();

        let mut tot_rules_applied = 0;

        while !traverser.at_end() {
            let num_rules_applied = Self::try_apply_rules_to_curr_entry(&mut traverser, entry_buf)?;
            tot_rules_applied += num_rules_applied;

            if num_rules_applied == 0 {
                // Unable to apply rule at current position, so advance the traverser.
                traverser.advance();
            }
        }

        Ok(tot_rules_applied)
    }

    fn try_apply_rules_to_curr_entry(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<usize> {
        traverser.get_next_n_elems_into_buf(MAX_WITNESS_ENTRIES_NEEDED_TO_MATCH_A_RULE, buf);

        match buf[0].clone() {
            WitnessEntry::Instruction(Instruction::EmptyRoot) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Empty)
            }
            WitnessEntry::Instruction(Instruction::Hash(h)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Hash(h))
            }
            WitnessEntry::Instruction(Instruction::Leaf(k, v)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(
                    1,
                    traverser,
                    NodeEntry::Leaf(k, LeafNodeData::Value(v.into())),
                )
            }
            WitnessEntry::Instruction(Instruction::Extension(k)) => {
                traverser.get_prev_n_elems_into_buf(1, buf);

                match &buf[0] {
                    WitnessEntry::Node(node) => Self::traverser_replace_prev_n_nodes_entry_helper(
                        2,
                        traverser,
                        NodeEntry::Extension(k, Box::new(node.clone())),
                    ),
                    _ => Self::invalid_witness_err(2, traverser),
                }
            }
            WitnessEntry::Instruction(Instruction::Code(c)) => {
                Self::traverser_replace_prev_n_nodes_entry_helper(1, traverser, NodeEntry::Code(c))
            }
            WitnessEntry::Instruction(Instruction::AccountLeaf(k, n, b, has_code, has_storage)) => {
                let (n_nodes_to_replace, account_node_code, s_trie) = match (has_code, has_storage)
                {
                    (false, false) => Self::match_account_leaf_no_code_and_no_storage(),
                    (false, true) => {
                        Self::match_account_leaf_no_code_but_has_storage(traverser, buf)
                    }
                    (true, false) => {
                        Self::match_account_leaf_has_code_but_no_storage(traverser, buf)
                    }
                    (true, true) => Self::match_account_leaf_has_code_and_storage(traverser, buf),
                }?;

                let account_leaf_data = AccountNodeData::new(n, b, s_trie, account_node_code);
                let leaf_node = WitnessEntry::Node(NodeEntry::Leaf(
                    k,
                    LeafNodeData::Account(account_leaf_data),
                ));
                traverser.replace_prev_n_entries_with_single_entry(n_nodes_to_replace, leaf_node);

                Ok(1)
            }
            WitnessEntry::Instruction(Instruction::Branch(mask)) => {
                Self::process_branch_instr(traverser, buf, mask)
            }
            _ => Ok(0),
        }
    }

    fn process_branch_instr(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
        mask: BranchMask,
    ) -> CompactParsingResult<usize> {
        let expected_number_of_preceding_nodes = mask.count_ones() as usize;

        traverser.get_prev_n_elems_into_buf(expected_number_of_preceding_nodes, buf);
        let number_available_preceding_elems = buf.len();

        if buf.len() != expected_number_of_preceding_nodes {
            return Err(CompactParsingError::IncorrectNumberOfNodesPrecedingBranch(
                mask,
                expected_number_of_preceding_nodes,
                number_available_preceding_elems,
                buf.clone(),
            ));
        }

        let mut branch_nodes = Self::create_empty_branch_node_entry();
        let mut curr_traverser_node_idx = 0;

        for (i, branch_node) in branch_nodes
            .iter_mut()
            .enumerate()
            .take(BRANCH_MAX_CHILDREN)
        {
            if mask as usize & (1 << i) != 0 {
                let entry_to_check = &buf[buf.len() - 1 - curr_traverser_node_idx];
                let node_entry = try_get_node_entry_from_witness_entry(entry_to_check)
                    .ok_or_else(|| {
                        let n_entries_behind_cursor =
                            number_available_preceding_elems - curr_traverser_node_idx;

                        CompactParsingError::UnexpectedPrecedingNodeFoundWhenProcessingRule(
                            n_entries_behind_cursor,
                            "Branch",
                            entry_to_check.to_string(),
                            buf.clone(),
                        )
                    })?
                    .clone();

                *branch_node = Some(Box::new(node_entry));
                curr_traverser_node_idx += 1;
            }
        }

        let number_of_nodes_traversed = curr_traverser_node_idx; // For readability.
        if curr_traverser_node_idx != buf.len() {
            return Err(CompactParsingError::MissingExpectedNodesPrecedingBranch(
                expected_number_of_preceding_nodes,
                number_of_nodes_traversed,
                mask,
                buf.clone(),
            ));
        }

        traverser.replace_prev_n_entries_with_single_entry(
            number_of_nodes_traversed + 1,
            NodeEntry::Branch(branch_nodes).into(),
        );
        Ok(1)
    }

    // ... Because we can't do `[None; 16]` without implementing `Copy`.
    const fn create_empty_branch_node_entry() -> [Option<Box<NodeEntry>>; 16] {
        [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None,
        ]
    }

    const fn match_account_leaf_no_code_and_no_storage(
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        Ok((1, None, None))
    }

    fn match_account_leaf_no_code_but_has_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(1, buf);

        match buf[0].clone() {
            WitnessEntry::Node(node) => {
                Self::try_create_and_insert_partial_trie_from_node(&node, None, 2, traverser)
            }
            _ => Self::invalid_witness_err(2, traverser),
        }
    }

    fn match_account_leaf_has_code_but_no_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(1, buf);

        match buf[0].clone() {
            WitnessEntry::Node(NodeEntry::Code(code)) => {
                Ok((2, Some(AccountNodeCode::CodeNode(code.clone())), None))
            }
            WitnessEntry::Node(NodeEntry::Hash(h)) => {
                Ok((2, Some(AccountNodeCode::HashNode(h)), None))
            }
            _ => Self::invalid_witness_err(2, traverser),
        }
    }

    fn match_account_leaf_has_code_and_storage(
        traverser: &mut CollapsableWitnessEntryTraverser,
        buf: &mut Vec<WitnessEntry>,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        traverser.get_prev_n_elems_into_buf(2, buf);

        match &buf[0..=1] {
            [WitnessEntry::Node(node), WitnessEntry::Node(NodeEntry::Code(c_bytes))] => {
                Self::try_create_and_insert_partial_trie_from_node(
                    node,
                    Some(c_bytes.clone().into()),
                    3,
                    traverser,
                )
            }
            [WitnessEntry::Node(node), WitnessEntry::Node(NodeEntry::Hash(c_hash))] => {
                Self::try_create_and_insert_partial_trie_from_node(
                    node,
                    Some((*c_hash).into()),
                    3,
                    traverser,
                )
            }
            _ => Self::invalid_witness_err(3, traverser),
        }
    }

    fn try_create_and_insert_partial_trie_from_node(
        node: &NodeEntry,
        account_node_code: Option<AccountNodeCode>,
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
    ) -> CompactParsingResult<(usize, Option<AccountNodeCode>, Option<HashedPartialTrie>)> {
        match Self::try_get_storage_root_node(node) {
            Some(storage_root_node) => {
                let s_trie_out = create_storage_partial_trie_from_compact_node(storage_root_node)?;
                Ok((n, account_node_code, Some(s_trie_out.trie)))
            }
            None => Self::invalid_witness_err(n, traverser),
        }
    }

    fn try_get_storage_root_node(node: &NodeEntry) -> Option<NodeEntry> {
        match node {
            NodeEntry::Code(_) => None,
            _ => Some(node.clone()),
        }
    }

    fn invalid_witness_err<T>(
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
    ) -> CompactParsingResult<T> {
        let adjacent_elems_buf = traverser.get_prev_n_elems(n).cloned().collect();

        Err(CompactParsingError::InvalidWitnessFormat(
            adjacent_elems_buf,
        ))
    }

    fn traverser_replace_prev_n_nodes_entry_helper(
        n: usize,
        traverser: &mut CollapsableWitnessEntryTraverser,
        entry: NodeEntry,
    ) -> CompactParsingResult<usize> {
        traverser.replace_prev_n_entries_with_single_entry(n, WitnessEntry::Node(entry));
        Ok(1)
    }
}

struct WitnessBytes<C: CompactCursor> {
    byte_cursor: C,
    instrs: WitnessEntries,
}

impl<C: CompactCursor> WitnessBytes<C> {
    fn new(witness_bytes: Vec<u8>) -> Self {
        Self {
            byte_cursor: C::new(witness_bytes),
            instrs: WitnessEntries::default(),
        }
    }

    fn process_into_instructions_and_header(
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

    #[allow(dead_code)]
    fn process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure(
        self,
    ) -> (InstructionAndBytesParsedFromBuf, CompactParsingResult<()>) {
        let mut instr_and_bytes_buf = Vec::new();
        let res = self.process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure_intern(&mut instr_and_bytes_buf);

        (instr_and_bytes_buf.into(), res)
    }

    #[allow(dead_code)]
    fn process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure_intern(
        mut self,
        instr_and_bytes_buf: &mut Vec<(Instruction, Vec<u8>)>,
    ) -> CompactParsingResult<()> {
        // Skip header.
        self.byte_cursor.intern().set_position(1);

        loop {
            let op_start_pos = self.byte_cursor.intern().position();
            self.process_operator()?;

            let instr_bytes = get_bytes_from_cursor(&mut self.byte_cursor, op_start_pos);

            let instr_added = self
                .instrs
                .intern
                .front()
                .cloned()
                .unwrap()
                .into_instruction()
                .unwrap();

            instr_and_bytes_buf.push((instr_added, instr_bytes));

            if self.byte_cursor.at_eof() {
                break;
            }
        }

        Ok(())
    }

    fn process_operator(&mut self) -> CompactParsingResult<()> {
        let opcode_byte = self.byte_cursor.read_byte()?;

        let opcode =
            Opcode::n(opcode_byte).ok_or(CompactParsingError::InvalidOpcode(opcode_byte))?;

        trace!("Processed \"{:?}\" opcode", opcode);

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
        }
    }

    fn process_leaf(&mut self) -> CompactParsingResult<()> {
        let key = key_bytes_to_nibbles(&self.byte_cursor.read_cbor_byte_array_to_vec("leaf key")?);
        let value_raw = self.byte_cursor.read_cbor_byte_array_to_vec("leaf value")?;

        self.push_entry(Instruction::Leaf(key, value_raw));
        Ok(())
    }

    fn process_extension(&mut self) -> CompactParsingResult<()> {
        let key = key_bytes_to_nibbles(
            &self
                .byte_cursor
                .read_cbor_byte_array_to_vec("extension key")?,
        );

        self.push_entry(Instruction::Extension(key));
        Ok(())
    }

    fn process_branch(&mut self) -> CompactParsingResult<()> {
        let mask = self.byte_cursor.read_t("mask")?;

        self.push_entry(Instruction::Branch(mask));
        Ok(())
    }

    fn process_hash(&mut self) -> CompactParsingResult<()> {
        let hash = self.byte_cursor.read_non_cbor_h256("hash")?;

        self.push_entry(Instruction::Hash(hash));
        Ok(())
    }

    fn process_code(&mut self) -> CompactParsingResult<()> {
        let code = self.byte_cursor.read_t("code")?;

        self.push_entry(Instruction::Code(code));
        Ok(())
    }

    fn process_account_leaf(&mut self) -> CompactParsingResult<()> {
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

    fn process_empty_root(&mut self) -> CompactParsingResult<()> {
        self.push_entry(Instruction::EmptyRoot);
        Ok(())
    }

    fn push_entry(&mut self, instr: Instruction) {
        self.instrs.push(instr.into())
    }

    fn parse_header(&mut self) -> CompactParsingResult<Header> {
        let h_byte = self
            .byte_cursor
            .read_byte()
            .map_err(|_| CompactParsingError::MissingHeader)?;

        Ok(Header { version: h_byte })
    }
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

trait CompactCursor {
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
struct CompactCursorFast {
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
struct DebugCompactCursor(CompactCursorFast);

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

/// We kind of want a wrapper around the actual data structure I think since
/// there's a good chance this will change a few times in the future.
#[derive(Debug, Default)]
pub struct WitnessEntries {
    // Yeah a LL is actually (unfortunately) a very good choice here. We will be doing a ton of
    // inserts mid-list, and the list can get very large. There might be a better choice for a data
    // structure, but for now, this will make performance not scale exponentially with list
    // size.
    intern: LinkedList<WitnessEntry>,
}

impl WitnessEntries {
    fn push(&mut self, entry: WitnessEntry) {
        self.intern.push_back(entry)
    }

    fn pop(&mut self) -> Option<WitnessEntry> {
        self.intern.pop_back()
    }

    fn create_collapsable_traverser(&mut self) -> CollapsableWitnessEntryTraverser {
        let entry_cursor = self.intern.cursor_front_mut();

        CollapsableWitnessEntryTraverser { entry_cursor }
    }

    fn len(&self) -> usize {
        self.intern.len()
    }
}

// It's not quite an iterator, so this is the next best name that I can come up
// with.
#[derive(Debug)]
struct CollapsableWitnessEntryTraverser<'a> {
    entry_cursor: CursorMut<'a, WitnessEntry>,
}

impl<'a> CollapsableWitnessEntryTraverser<'a> {
    fn advance(&mut self) {
        self.entry_cursor.move_next();
    }

    fn get_next_n_elems(&self, n: usize) -> impl Iterator<Item = &WitnessEntry> {
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

    fn get_prev_n_elems(&self, n: usize) -> impl Iterator<Item = &WitnessEntry> {
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
    fn get_prev_n_elems_into_buf(&self, n: usize, buf: &mut Vec<WitnessEntry>) {
        buf.clear();
        buf.extend(self.get_prev_n_elems(n).cloned())
    }

    /// Get the next `n` elements into a buf. Note that this includes the
    /// element that we are currently pointing to.
    fn get_next_n_elems_into_buf(&self, n: usize, buf: &mut Vec<WitnessEntry>) {
        buf.clear();
        buf.extend(self.get_next_n_elems(n).cloned());
    }

    // Inclusive.
    fn replace_prev_n_entries_with_single_entry(&mut self, n: usize, entry: WitnessEntry) {
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

    fn at_end(&self) -> bool {
        self.entry_cursor.as_cursor().current().is_none()
    }
}

const fn try_get_node_entry_from_witness_entry(entry: &WitnessEntry) -> Option<&NodeEntry> {
    match entry {
        WitnessEntry::Node(n_entry) => Some(n_entry),
        _ => None,
    }
}

#[derive(Debug, Default)]
pub(crate) struct PartialTriePreImages {
    pub state: HashedPartialTrie,
    pub storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
}

/// The output we get from processing prestate compact into the trie format of
/// `mpt_trie`.
///
/// Note that this format contains storage tries embedded within the state trie,
/// so there may be multiple tries inside this output. Also note that the
/// bytecode (instead of just the code hash) may be embedded directly in this
/// format.
#[derive(Debug)]
pub struct ProcessedCompactOutput {
    /// The header of the compact.
    pub header: Header,

    /// The actual processed `mpt_trie` tries and additional code hash mappings
    /// from the compact.
    pub witness_out: StateTrieExtractionOutput,
}

/// Processes the compact prestate into the trie format of `mpt_trie`.
pub fn process_compact_prestate(
    state: TrieCompact,
) -> CompactParsingResult<ProcessedCompactOutput> {
    process_compact_prestate_common(state, ParserState::create_and_extract_header)
}

/// Processes the compact prestate into the trie format of `mpt_trie`. Also
/// enables heavy debug traces during processing.
// TODO: Move behind a feature flag...
pub fn process_compact_prestate_debug(
    state: TrieCompact,
) -> CompactParsingResult<ProcessedCompactOutput> {
    process_compact_prestate_common(state, ParserState::create_and_extract_header_debug)
}

fn process_compact_prestate_common(
    state: TrieCompact,
    create_and_extract_header_f: fn(Vec<u8>) -> CompactParsingResult<(Header, ParserState)>,
) -> CompactParsingResult<ProcessedCompactOutput> {
    let (header, parser) = create_and_extract_header_f(state.0)?;
    let witness_out = parser.parse()?;

    let out = ProcessedCompactOutput {
        header,
        witness_out,
    };

    Ok(out)
}

// TODO: Move behind a feature flag just used for debugging (but probably not
// `debug`)...
#[allow(dead_code)]
fn parse_just_to_instructions(bytes: Vec<u8>) -> CompactParsingResult<Vec<Instruction>> {
    let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(bytes);
    let (_, entries) = witness_bytes.process_into_instructions_and_header()?;

    Ok(entries
        .intern
        .into_iter()
        .map(|entry| match entry {
            WitnessEntry::Instruction(instr) => instr,
            _ => unreachable!(
                "Found a non-instruction at a stage when we should only have instructions!"
            ),
        })
        .collect())
}

// Using struct to make printing this nicer easier.
#[derive(Debug)]
struct InstructionAndBytesParsedFromBuf(Vec<(Instruction, Vec<u8>)>);

impl From<Vec<(Instruction, Vec<u8>)>> for InstructionAndBytesParsedFromBuf {
    fn from(v: Vec<(Instruction, Vec<u8>)>) -> Self {
        Self(v)
    }
}

impl Display for InstructionAndBytesParsedFromBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Instructions and bytes there were parsed from:")?;

        for (instr, parsed_from_bytes) in &self.0 {
            writeln!(
                f,
                "Instruction: {}, Bytes: {}",
                instr,
                hex::encode(parsed_from_bytes)
            )?;
        }

        Ok(())
    }
}

// TODO: Also move behind a feature flag...
#[allow(dead_code)]
fn parse_to_instructions_and_bytes_for_instruction(
    bytes: Vec<u8>,
) -> (InstructionAndBytesParsedFromBuf, CompactParsingResult<()>) {
    let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(bytes);
    witness_bytes
        .process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure()
}

fn key_bytes_to_nibbles(bytes: &[u8]) -> Nibbles {
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

struct CursorBytesDebugInfo {
    bytes_hex: String,
    hex_start_pos: usize,
}

fn get_bytes_and_debug_info_from_cursor<C: CompactCursor>(
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

fn get_bytes_from_cursor<C: CompactCursor>(cursor: &mut C, cursor_start_pos: u64) -> Vec<u8> {
    let cursor_end_pos = cursor.intern().position();
    let mut cloned_cursor = cursor.intern().clone();

    // Rewind the cursor.
    cloned_cursor.set_position(cursor_start_pos);

    let num_bytes_read = (cursor_end_pos - cursor_start_pos) as usize;
    let mut t_bytes = vec![0; num_bytes_read];
    cloned_cursor.read_exact(&mut t_bytes).unwrap();

    t_bytes
}

#[cfg(test)]
mod tests {
    use mpt_trie::nibbles::Nibbles;

    use super::{key_bytes_to_nibbles, parse_just_to_instructions, Instruction};
    use crate::compact::complex_test_payloads::{
        TEST_PAYLOAD_1, TEST_PAYLOAD_2, TEST_PAYLOAD_3, TEST_PAYLOAD_4, TEST_PAYLOAD_5,
        TEST_PAYLOAD_6,
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
}
