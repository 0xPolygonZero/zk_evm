//! Logic to convert the decoded compact into a `smt_trie`. This is the final
//! stage in the decoding process.

use std::collections::HashMap;

use ethereum_types::{Address, U256};

use super::compact_prestate_processing::{
    CompactParsingResult, NodeEntry, SmtNodeType, WitnessEntry,
};
use crate::types::{CodeHash, TrieRootHash};

/// Output from constructing a storage trie from smt compact.
#[derive(Debug, Default)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub state_smt: Vec<U256>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,
}

impl SmtStateTrieExtractionOutput {
    fn process_branch_smt_node(
        &mut self,
        l_child: &Option<Box<NodeEntry>>,
        r_child: &Option<Box<NodeEntry>>,
    ) {
    }

    fn process_hash_node(&mut self, hash: &TrieRootHash) {}

    fn process_code_node(&mut self, c_bytes: &[u8]) {}

    fn process_smt_leaf(
        &mut self,
        n_type: SmtNodeType,
        addr: &[u8],
        slot_bytes: &[u8],
        slot_val: &[u8],
    ) {
    }
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

    create_smt_trie_from_compact_node_rec(&node, &mut output)?;

    Ok(output)
}

fn create_smt_trie_from_compact_node_rec(
    curr_node: &NodeEntry,
    output: &mut SmtStateTrieExtractionOutput,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::BranchSMT([l_child, r_child]) => {
            output.process_branch_smt_node(l_child, r_child)
        }
        NodeEntry::Code(c_bytes) => output.process_code_node(c_bytes),
        NodeEntry::Empty => (),
        NodeEntry::Hash(h) => output.process_hash_node(h),
        NodeEntry::SMTLeaf(n_type, addr_bytes, slot_bytes, slot_val) => {
            output.process_smt_leaf(*n_type, addr_bytes, slot_bytes, slot_val)
        }
        _ => unreachable!(), // TODO: Remove once we split `NodeEntry` into two types...
    }

    Ok(())
}
