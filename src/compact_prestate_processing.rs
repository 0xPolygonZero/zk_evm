//! Processing for the compact format as specified here: https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md

use std::fmt::{self, Display};

use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug)]
struct Header {
    version: u8,
}

impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Erigon block witness version {}", self.version)
    }
}

#[derive(Debug, Deserialize, Serialize)]
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
enum Operator {
    Leaf(),
    Extension,
    Branch,
    Hash,
    Code,
    AccountLeaf,
    EmptyRoot,
}

#[derive(Debug, Default)]
struct ParserState {
    stack: Vec<StackEntry>,
}

impl ParserState {
    fn process_operator(
        &mut self,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<Operator> {
        let opcode_byte = bytes
            .next()
            .ok_or(CompactParsingError::UnexpectedEndOfStream)?;
        let opcode =
            Opcode::n(opcode_byte).ok_or(CompactParsingError::InvalidOperator(opcode_byte))?;

        self.process_data_following_opcode(opcode, bytes)?;

        todo!()
    }

    fn process_data_following_opcode(
        &mut self,
        opcode: Opcode,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<()> {
        match opcode {
            Opcode::Leaf => self.process_leaf(bytes),
            Opcode::Extension => self.process_extension(bytes),
            Opcode::Branch => self.process_branch(bytes),
            Opcode::Hash => self.process_hash(bytes),
            Opcode::Code => self.process_code(bytes),
            Opcode::AccountLeaf => self.process_leaf(bytes),
            Opcode::EmptyRoot => self.process_empty_root(bytes),
        }
    }

    fn process_leaf(&mut self, _bytes: &mut impl Iterator<Item = u8>) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_extension(
        &mut self,
        _bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_branch(
        &mut self,
        _bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_hash(&mut self, _bytes: &mut impl Iterator<Item = u8>) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_code(&mut self, _bytes: &mut impl Iterator<Item = u8>) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_account_leaf(
        &mut self,
        _bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<()> {
        todo!()
    }

    fn process_empty_root(
        &mut self,
        _bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<()> {
        todo!()
    }
}

#[derive(Debug)]
enum StackEntry {
    AccountLeaf(AccountLeafData),
    Code(Vec<u8>),
    Empty,
    Hash(NodeHash),
    Leaf(Key, Value),
    Extension(Key),
}

#[derive(Debug)]
struct AccountLeafData {}

pub(crate) fn process_compact_prestate(
    state: TrieCompact,
) -> CompactParsingResult<HashedPartialTrie> {
    let mut parser = ParserState::default();
    let mut byte_iter = state.bytes.into_iter();

    let _header = parse_header(&mut byte_iter)?;

    loop {
        let _operator = parser.process_operator(&mut byte_iter)?;
    }

    todo!()
}

fn parse_header(bytes: &mut impl Iterator<Item = u8>) -> CompactParsingResult<Header> {
    let h_byte = bytes.next().ok_or(CompactParsingError::MissingHeader)?;

    Ok(Header { version: h_byte })
}
