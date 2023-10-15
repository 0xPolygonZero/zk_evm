//! Processing for the compact format as specified here: https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md

use std::{
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

#[derive(Debug)]
struct Header {
    version: u8,
}

impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Erigon block witness version {}", self.version)
    }
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
enum Operator {
    Leaf(),
    Extension,
    Branch,
    Hash,
    Code,
    AccountLeaf,
    EmptyRoot,
}

#[derive(Debug, Deserialize)]
struct LeafData {
    key: Key,
    value: Vec<u8>,
}

#[derive(Debug)]
struct ParserState {
    stack: Vec<StackEntry>,
    byte_cursor: CompactCursor,
}

impl ParserState {
    fn new(payload_bytes: Vec<u8>) -> Self {
        let byte_cursor = CompactCursor {
            intern: Cursor::new(payload_bytes),
        };

        Self {
            byte_cursor,
            stack: Vec::default(),
        }
    }

    fn process_stream(self) -> CompactParsingResult<HashedPartialTrie> {
        let (_, trie) = self.process_stream_and_get_header()?;
        Ok(trie)
    }

    fn process_stream_and_get_header(
        mut self,
    ) -> CompactParsingResult<(Header, HashedPartialTrie)> {
        let header = self.parse_header()?;

        loop {
            let _operator = self.process_operator()?;

            if self.byte_cursor.at_eof() {
                break;
            }
        }

        // TODO
        Ok((header, HashedPartialTrie::default()))
    }

    fn parse_header(&mut self) -> CompactParsingResult<Header> {
        let h_byte = self
            .byte_cursor
            .read_byte()
            .map_err(|_| CompactParsingError::MissingHeader)?;

        Ok(Header { version: h_byte })
    }

    fn process_operator(&mut self) -> CompactParsingResult<Operator> {
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
        self.push_to_stack(StackEntry::Empty);
        Ok(())
    }

    fn push_to_stack(&mut self, entry: StackEntry) {
        self.stack.push(entry)
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
) -> CompactParsingResult<HashedPartialTrie> {
    let parser = ParserState::new(state.bytes);
    parser.process_stream()
}
