//! Logic to convert the decoded compact into a `smt_trie`. This is the final
//! stage in the decoding process.

use std::collections::HashMap;

use ethereum_types::U256;

use super::compact_prestate_processing::{CompactParsingResult, NodeEntry, WitnessEntry};
use crate::types::CodeHash;

/// Output from constructing a storage trie from smt compact.
#[derive(Debug, Default)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub state_smt: Vec<U256>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,
}

// TODO: Merge both `SMT` & `MPT` versions of this function into a single one...
pub(super) fn create_smt_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");

    create_smt_trie_from_compact_node(remaining_node)
}

fn create_smt_trie_from_compact_node(
    node: NodeEntry,
) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
    let mut output = SmtStateTrieExtractionOutput::default();

    todo!()
    // create_partial_trie_from_compact_node_rec(Nibbles::default(), &node, &mut
    // output)?;

    // Ok(output)
}
