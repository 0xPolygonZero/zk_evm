//! Logic to convert the decoded compact into a `smt_trie`. This is the final
//! stage in the decoding process.

use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, U256};
use keccak_hash::H256;
use mpt_trie::nibbles::Nibbles;
use plonky2::{hash::hash_types::HashOut, plonk::config::GenericHashOut};

use super::{
    compact_processing_common::{
        CompactCursor, CompactParsingError, CompactParsingResult, DebugCompactCursor, Header,
        NodeEntry, ParserState, WitnessBytes, WitnessEntries, WitnessEntry,
    },
    compact_smt_processing::SmtNodeType,
    compact_to_mpt_trie::{create_mpt_trie_from_remaining_witness_elem, StateTrieExtractionOutput},
    tmp::{
        bits::Bits,
        db::MemoryDb,
        keys::{key_balance, key_code, key_code_length, key_nonce, key_storage},
        smt::{Key, Smt},
    },
};
use crate::{
    compact::compact_processing_common::Opcode,
    types::{CodeHash, TrieRootHash},
    utils::hash,
};

/// Output from constructing a storage trie from smt compact.
#[derive(Debug, Default)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub state_smt_trie: Smt<MemoryDb>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,
}

impl SmtStateTrieExtractionOutput {
    fn process_branch_smt_node(
        &mut self,
        curr_key: Bits,
        l_child: &Option<Box<NodeEntry>>,
        r_child: &Option<Box<NodeEntry>>,
    ) {
        if let Some(l_child) = l_child {
            let mut lkey = curr_key;
            lkey.push_bit(false);
            create_smt_trie_from_compact_node_rec(lkey, l_child, self);
        }

        if let Some(r_child) = r_child {
            let mut rkey = curr_key;
            rkey.push_bit(true);
            create_smt_trie_from_compact_node_rec(rkey, r_child, self);
        }
    }

    fn process_hash_node(&mut self, curr_key: Bits, h: &TrieRootHash) {
        // Note: This may be incorrect in how to construct the key.
        self.state_smt_trie
            .set_hash(curr_key, HashOut::from_bytes(h.as_bytes()));
    }

    fn process_code_node(&mut self, c_bytes: &Vec<u8>) {
        let c_hash = hash(c_bytes);
        self.code.insert(c_hash, c_bytes.clone());
    }

    fn process_smt_leaf(
        &mut self,
        n_type: SmtNodeType,
        addr: &[u8],
        slot_bytes: &[u8],
        val_bytes: &[u8],
    ) {
        let addr = Address::from_slice(addr);
        let val = U256::from_big_endian(val_bytes);

        let key = match n_type {
            SmtNodeType::Balance => key_balance(addr),
            SmtNodeType::Nonce => key_nonce(addr),
            SmtNodeType::Code => key_code(addr),
            SmtNodeType::Storage => {
                // Massive assumption: Is the slot unhashed?
                let slot = U256::from_big_endian(slot_bytes);
                key_storage(addr, slot)
            }
            SmtNodeType::CodeLength => key_code_length(addr),
        };

        self.state_smt_trie.set(key, val)
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

    create_smt_trie_from_compact_node_rec(Bits::default(), &node, &mut output)?;

    Ok(output)
}

fn create_smt_trie_from_compact_node_rec(
    curr_key: Bits,
    curr_node: &NodeEntry,
    output: &mut SmtStateTrieExtractionOutput,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::BranchSMT([l_child, r_child]) => {
            output.process_branch_smt_node(curr_key, l_child, r_child)
        }
        NodeEntry::Code(c_bytes) => output.process_code_node(c_bytes),
        NodeEntry::Empty => (),
        NodeEntry::Hash(h) => output.process_hash_node(curr_key, h),
        NodeEntry::SMTLeaf(n_type, addr_bytes, slot_bytes, slot_val) => {
            output.process_smt_leaf(*n_type, addr_bytes, slot_bytes, slot_val)
        }
        _ => unreachable!(), // TODO: Remove once we split `NodeEntry` into two types...
    }

    Ok(())
}
