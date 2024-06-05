//! Logic to convert the decoded compact into a `smt_trie`. This is the final
//! stage in the decoding process.

use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, U256};
use plonky2::field::types::Field;
use smt_trie::{
    bits::Bits,
    db::MemoryDb,
    keys::{key_balance, key_code, key_code_length, key_nonce, key_storage},
    smt::{HashOut, Key, Smt, F},
};

use super::compact_processing_common::{
    Balance, CompactDecodingResult, CompactParsingResult, NodeEntry, Nonce, SmtLeafNodeType,
};
use crate::{
    decoding_smt::SmtTrieInner,
    types::{AccountInfo, CodeHash, HashedAccountAddr, TrieRootHash},
    utils::{hash, u256_to_h256},
};

/// Currently, the smt library requires that all calls to [`set_hash`] must
/// occur before any [`set`] calls, so we're using an intermediate type to
/// buffer all calls.
#[derive(Debug, Default)]
struct SmtStateTrieExtractionIntermediateOutput {
    leaf_inserts: Vec<(Key, U256)>,
    hash_inserts: Vec<(Bits, HashOut)>,

    account_meta: HashMap<Address, AccountInfo>,
}

impl SmtStateTrieExtractionIntermediateOutput {
    fn into_smt_trie_and_meta(self) -> (Smt<MemoryDb>, HashMap<Address, AccountInfo>) {
        let mut state_smt_trie = Smt::default();

        for (k, h) in self.hash_inserts {
            state_smt_trie.set_hash(k, h);
        }

        for (k, v) in self.leaf_inserts {
            state_smt_trie.set(k, v);
        }

        (state_smt_trie, self.account_meta)
    }
}

/// Output from constructing a storage trie from smt compact.
#[derive(Debug)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub trie: Smt<MemoryDb>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,

    /// We need some additional account meta data that is not present in the smt
    /// format, so we collect it during construction of smt tries instead.
    pub account_meta: HashMap<Address, AccountInfo>,
}

impl SmtStateTrieExtractionIntermediateOutput {
    fn process_branch_smt_node(
        &mut self,
        curr_key: Bits,
        l_child: &Option<Box<NodeEntry>>,
        r_child: &Option<Box<NodeEntry>>,
    ) -> CompactDecodingResult<()> {
        if let Some(l_child) = l_child {
            let mut lkey = curr_key;
            lkey.push_bit(false);
            create_smt_trie_from_compact_node_rec(lkey, l_child, self)?;
        }

        if let Some(r_child) = r_child {
            let mut rkey = curr_key;
            rkey.push_bit(true);
            create_smt_trie_from_compact_node_rec(rkey, r_child, self)?;
        }

        Ok(())
    }

    fn process_hash_node(&mut self, curr_key: Bits, h: &TrieRootHash) {
        let hash_v = HashOut {
            elements: h.into_uint().0.map(F::from_canonical_u64),
        };

        self.hash_inserts.push((curr_key, hash_v));
    }

    fn process_smt_leaf(
        &mut self,
        n_type: SmtLeafNodeType,
        addr: &[u8],
        slot_bytes: &[u8],
        val_bytes: &[u8],
    ) {
        let addr = Address::from_slice(addr);
        let val = U256::from_big_endian(val_bytes);

        let key = match n_type {
            SmtLeafNodeType::Balance => {
                self.create_smt_key_and_update_meta(&addr, val, |acc, v| acc.balance = v);
                key_balance(addr)
            }
            SmtLeafNodeType::Nonce => {
                self.create_smt_key_and_update_meta(&addr, val, |acc, v| acc.nonce = v);
                key_nonce(addr)
            }
            SmtLeafNodeType::Code => {
                self.create_smt_key_and_update_meta(&addr, val, |acc, v| {
                    acc.c_hash = u256_to_h256(&v)
                });
                key_code(addr)
            }
            SmtLeafNodeType::Storage => {
                let slot = U256::from_big_endian(slot_bytes);
                key_storage(addr, slot)
            }
            SmtLeafNodeType::CodeLength => key_code_length(addr),
        };

        self.leaf_inserts.push((key, val))
    }

    fn create_smt_key_and_update_meta<F>(&mut self, addr: &Address, val: U256, update_meta_f: F)
    where
        F: Fn(&mut AccountInfo, U256),
    {
        let acc = self.account_meta.entry(*addr).or_default();
        update_meta_f(acc, val)
    }
}

// TODO: Merge both `SMT` & `MPT` versions of this function into a single one...
pub(super) fn create_smt_trie_and_meta_from_remaining_witness_elem(
    remaining_entry: NodeEntry,
    code: HashMap<CodeHash, Vec<u8>>,
) -> CompactParsingResult<SmtStateTrieExtractionOutput> {
    let (state_trie, account_meta) = create_smt_trie_from_compact_node(remaining_entry)?;

    Ok(SmtStateTrieExtractionOutput {
        trie: state_trie,
        code,
        account_meta,
    })
}

fn create_smt_trie_from_compact_node(
    node: NodeEntry,
) -> CompactParsingResult<(SmtTrieInner, HashMap<Address, AccountInfo>)> {
    let mut output = SmtStateTrieExtractionIntermediateOutput::default();
    create_smt_trie_from_compact_node_rec(Bits::default(), &node, &mut output)?;

    Ok(output.into_smt_trie_and_meta())
}

fn create_smt_trie_from_compact_node_rec(
    curr_key: Bits,
    curr_node: &NodeEntry,
    output: &mut SmtStateTrieExtractionIntermediateOutput,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::BranchSMT([l_child, r_child]) => {
            output.process_branch_smt_node(curr_key, l_child, r_child)?
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
