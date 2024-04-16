//! Logic to convert the decoded compact into a `smt_trie`. This is the final
//! stage in the decoding process.

use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, U256};
use keccak_hash::H256;
use mpt_trie::nibbles::Nibbles;
use plonky2::plonk::config::GenericHashOut;

use super::{
    compact_processing_common::{
        CompactCursor, CompactParsingError, CompactParsingResult, DebugCompactCursor, Header,
        NodeEntry, ParserState, SMTLeafNode, WitnessBytes, WitnessEntries, WitnessEntry,
    },
    compact_smt_processing::SmtNodeType,
    compact_to_mpt_trie::{create_mpt_trie_from_remaining_witness_elem, StateTrieExtractionOutput},
    tmp::{
        bits::Bits,
        db::MemoryDb,
        keys::{key_balance, key_code, key_code_length, key_nonce, key_storage},
        smt::{HashOut, Key, Smt},
    },
};
use crate::{
    compact::compact_processing_common::Opcode,
    types::{CodeHash, TrieRootHash},
    utils::hash,
};

/// Currently, the smt library requires that all calls to [`set_hash`] must
/// occur before any [`set`] calls, so we're using an intermediate type to
/// buffer all calls.
#[derive(Debug, Default)]
struct SmtStateTrieExtractionIntermediateOutput {
    leaf_inserts: Vec<(Key, U256)>,
    hash_inserts: Vec<(Bits, HashOut)>,
}

impl SmtStateTrieExtractionIntermediateOutput {
    fn into_smt_trie(self) -> Smt<MemoryDb> {
        let mut state_smt_trie = Smt::default();

        for (k, h) in self.hash_inserts {
            state_smt_trie.set_hash(k, h);
        }

        println!("state_smt_trie after hash inserts: {:?}", state_smt_trie);

        for (k, v) in self.leaf_inserts {
            state_smt_trie.set(k, v);
        }
        println!("state_smt_trie after leaf inserts: {:?}", state_smt_trie);

        state_smt_trie
    }
}

/// Output from constructing a storage trie from smt compact.
#[derive(Debug)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub state_trie: Smt<MemoryDb>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,
}

impl SmtStateTrieExtractionIntermediateOutput {
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
        println!("--------------------- Hash: {:?}", h);
        println!("--------------------- curr_key: {:?}", curr_key);
        self.hash_inserts
            .push((curr_key, HashOut::from_bytes(h.as_bytes())));
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
                let key = key_storage(addr, slot);
                key_storage(addr, slot)
            }
            SmtNodeType::CodeLength => key_code_length(addr),
        };

        self.leaf_inserts.push((key, val))
    }
}

// TODO: Merge both `SMT` & `MPT` versions of this function into a single one...
pub(super) fn create_smt_trie_from_remaining_witness_elem(
    remaining_entry: NodeEntry,
    code: HashMap<CodeHash, Vec<u8>>,
) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
    let state_trie = create_smt_trie_from_compact_node(remaining_entry)?;

    Ok(SmtStateTrieExtractionOutput { state_trie, code })
}

fn create_smt_trie_from_compact_node(node: NodeEntry) -> CompactParsingResult<Smt<MemoryDb>> {
    let mut output = SmtStateTrieExtractionIntermediateOutput::default();
    create_smt_trie_from_compact_node_rec(Bits::default(), &node, &mut output)?;

    Ok(output.into_smt_trie())
}

fn create_smt_trie_from_compact_node_rec(
    curr_key: Bits,
    curr_node: &NodeEntry,
    output: &mut SmtStateTrieExtractionIntermediateOutput,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::BranchSMT([l_child, r_child]) => {
            output.process_branch_smt_node(curr_key, l_child, r_child)
        }
        NodeEntry::Empty => (),
        NodeEntry::Hash(h) => output.process_hash_node(curr_key, h),
        NodeEntry::SMTLeaf(n_type, addr_bytes, slot_bytes, slot_val) => {
            output.process_smt_leaf(*n_type, addr_bytes, slot_bytes, slot_val)
        }
        _ => unreachable!(), // TODO: Remove once we split `NodeEntry` into two types...
    }

    Ok(())
}
