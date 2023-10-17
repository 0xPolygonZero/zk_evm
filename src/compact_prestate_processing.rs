//! Processing for the compact format as specified here: https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md

use std::{
    collections::VecDeque,
    fmt::{self, Display},
    io::{Cursor, Read},
};

use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::H256;
use serde::Deserialize;
use thiserror::Error;

use crate::trace_protocol::TrieCompact;

pub type CompactParsingResult<T> = Result<T, CompactParsingError>;

type NodeHash = H256;
type Value = Vec<u8>;

#[derive(Debug, Error)]
pub enum CompactParsingError {
    #[error("Missing header")]
    MissingHeader,

    #[error("Invalid opcode operator (\"{0:x}\"")]
    InvalidOperator(u8),

    #[error("Reached the end of the byte stream when we still expected more data")]
    UnexpectedEndOfStream,

    #[error("Unable to parse an expected byte vector (error: {0})")]
    InvalidByteVector(String),
}

#[derive(Debug, Deserialize)]
struct Key {
    is_even: bool,
    bytes: Vec<u8>,
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

#[derive(Debug)]
enum StackEntry {
    Instruction(Instruction),
    Node(NodeEntry),
}

#[derive(Debug)]
enum Instruction {
    Leaf(),
    Extension,
    Branch,
    Hash,
    Code,
    AccountLeaf,
    EmptyRoot,
}

impl From<Instruction> for StackEntry {
    fn from(v: Instruction) -> Self {
        Self::Instruction(v)
    }
}

#[derive(Debug)]
enum NodeEntry {
    AccountLeaf(AccountLeafData),
    Code(Vec<u8>),
    Empty,
    Hash(NodeHash),
    Leaf(Key, Value),
    Extension(Key),
}

#[derive(Debug)]
struct AccountLeafData {}

#[derive(Debug, Deserialize)]
struct LeafData {
    key: Key,
    value: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Header {
    version: u8,
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
struct ParserState {
    stack: VecDeque<StackEntry>,
}

impl ParserState {
    fn create_and_extract_header(
        witness_bytes_raw: Vec<u8>,
    ) -> CompactParsingResult<(Header, Self)> {
        let witness_bytes = WitnessBytes::new(witness_bytes_raw);
        let (header, stack) = witness_bytes.process_into_instructions_and_header()?;

        let p_state = Self { stack };

        Ok((header, p_state))
    }

    fn parse(self) -> CompactParsingResult<HashedPartialTrie> {
        let trie = self.parse_into_trie()?;
        Ok(trie)
    }

    fn parse_into_trie(mut self) -> CompactParsingResult<HashedPartialTrie> {
        loop {
            let num_rules_applied = self.apply_rules_to_stack();

            if num_rules_applied == 0 {
                break;
            }
        }

        todo!()
    }

    fn apply_rules_to_stack(&mut self) -> usize {
        todo!()
    }
}

struct WitnessBytes {
    byte_cursor: CompactCursor,
    instrs: VecDeque<StackEntry>,
}

impl WitnessBytes {
    fn new(witness_bytes: Vec<u8>) -> Self {
        Self {
            byte_cursor: CompactCursor {
                intern: Cursor::new(witness_bytes),
            },
            instrs: VecDeque::default(),
        }
    }

    fn process_into_instructions_and_header(
        mut self,
    ) -> CompactParsingResult<(Header, VecDeque<StackEntry>)> {
        let header = self.parse_header()?;

        // TODO
        loop {
            let instr = self.process_operator()?;
            self.instrs.push_front(instr.into());

            if self.byte_cursor.at_eof() {
                break;
            }
        }

        Ok((header, self.instrs))
    }

    fn process_operator(&mut self) -> CompactParsingResult<Instruction> {
        let opcode_byte = self.byte_cursor.read_byte()?;

        let opcode =
            Opcode::n(opcode_byte).ok_or(CompactParsingError::InvalidOperator(opcode_byte))?;

        self.process_data_following_opcode(opcode)?;

        todo!()
    }

    fn process_data_following_opcode(&mut self, opcode: Opcode) -> CompactParsingResult<()> {
        match opcode {
            Opcode::Leaf => self.process_leaf(),
            Opcode::Extension => self.process_extension(),
            Opcode::Branch => self.process_branch(),
            Opcode::Hash => self.process_hash(),
            Opcode::Code => self.process_code(),
            Opcode::AccountLeaf => self.process_leaf(),
            Opcode::EmptyRoot => self.process_empty_root(),
        }
    }

    fn process_leaf(&mut self) -> CompactParsingResult<()> {
        let _key_raw = self.byte_cursor.read_byte_array()?;
        let _value_raw = self.byte_cursor.read_byte_array()?;

        todo!()
    }

    fn process_extension(&mut self) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_branch(&mut self) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_hash(&mut self) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_code(&mut self) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_account_leaf(&mut self) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_empty_root(&mut self) -> CompactParsingResult<()> {
        self.push_to_stack(Instruction::EmptyRoot);
        Ok(())
    }

    fn push_to_stack(&mut self, instr: Instruction) {
        self.instrs.push_front(instr.into())
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
struct CompactCursor {
    intern: Cursor<Vec<u8>>,
}

impl CompactCursor {
    fn read_byte(&mut self) -> CompactParsingResult<u8> {
        let mut single_byte_buf = [0];

        // Assume this is always caused by hitting the end of the stream?
        self.intern
            .read_exact(&mut single_byte_buf)
            .map_err(|_err| CompactParsingError::UnexpectedEndOfStream)?;

        Ok(single_byte_buf[0])
    }

    fn read_byte_array(&mut self) -> CompactParsingResult<Vec<u8>> {
        ciborium::from_reader(&mut self.intern)
            .map_err(|err| CompactParsingError::InvalidByteVector(err.to_string()))
    }

    fn at_eof(&self) -> bool {
        self.intern.position() as usize == self.intern.get_ref().len()
    }
}

pub(crate) fn process_compact_prestate(
    state: TrieCompact,
) -> CompactParsingResult<(Header, HashedPartialTrie)> {
    let (header, parser) = ParserState::create_and_extract_header(state.bytes)?;
    let trie = parser.parse()?;

    Ok((header, trie))
}
