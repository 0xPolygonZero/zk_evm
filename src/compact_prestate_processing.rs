//! Processing for the compact format as specified here: https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md

use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::H256;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::trace_protocol::TrieCompact;

pub type CompactParsingResult<T> = Result<T, CompactParsingError>;

type NodeHash = H256;
type Value = Vec<u8>;

#[derive(Debug, Error)]
pub enum CompactParsingError {}

#[derive(Debug)]
struct Header {
    version: u8,
}

#[derive(Debug, Deserialize, Serialize)]
struct Key {
    is_even: bool,
    bytes: Vec<u8>,
}

#[derive(Debug)]
enum OperatorCode {
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
        _bytes: &mut impl Iterator<Item = u8>,
    ) -> CompactParsingResult<Operator> {
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

pub(crate) fn process_compact_prestate(state: TrieCompact) -> HashedPartialTrie {
    let _parser = ParserState::default();
    let _byte_iter = state.bytes.into_iter();

    loop {}

    todo!()
}

fn parse_header(_bytes: &mut impl Iterator<Item = u8>) -> CompactParsingResult<Header> {
    todo!()
}
