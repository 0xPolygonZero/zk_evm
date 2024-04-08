// TODO: Rename (or split) module as it's no longer just dealing specifically
// just with `HashedPartialTries`...
//! Logic to convert the decoded compact into a `mpt_trie`
//! [`HashedPartialTrie`]. This is the final stage in the decoding process.

use std::{
    collections::HashMap,
    fmt::{self, Display},
};

use ethereum_types::U256;
use evm_arithmetization_mpt::generation::mpt::SMTLeafNodeRlp;
use log::trace;
use mpt_trie::{
    nibbles::{Nibble, Nibbles},
    partial_trie::{HashedPartialTrie, PartialTrie},
};

use super::compact_prestate_processing::{
    AccountNodeCode, AccountNodeData, CompactParsingError, CompactParsingResult, LeafNodeData,
    NodeEntry, WitnessEntry,
};
use crate::{
    aliased_crate_types::MptAccountRlp,
    decoding::TrieType,
    types::{
        CodeHash, HashedAccountAddr, HashedAccountAddrNibbles, TrieRootHash, EMPTY_CODE_HASH,
        EMPTY_TRIE_HASH,
    },
    utils::hash,
};

/// A trait to represent building either a state or storage trie from compact
/// output.
///
/// Because building state & storage tries from compact shares a huge amount of
/// common code, it makes sense to use a trait and allow each trie type to use
/// slightly different logic for processing code and leaf nodes.
trait CompactToPartialTrieExtractionOutput {
    /// Traverses down each child in the branch and adds the branch's [`Nibble`]
    /// to our current key.
    fn process_branch(
        &mut self,
        curr_key: Nibbles,
        children: &[Option<Box<NodeEntry>>],
    ) -> CompactParsingResult<()> {
        for (i, slot) in children.iter().enumerate().take(16) {
            if let Some(child) = slot {
                // TODO: Seriously update `mpt_trie` to have a better API...
                let mut new_k = curr_key;
                new_k.push_nibble_back(i as Nibble);
                create_partial_trie_from_compact_node_rec(new_k, child, self)?;
            }
        }

        Ok(())
    }

    // TODO: This is here only for a rebase, and needs to be removed ASAP!
    fn process_branch_smt(
        &mut self,
        curr_key: Nibbles,
        branch: &[Option<Box<NodeEntry>>],
    ) -> CompactParsingResult<()> {
        println!("-------------- branch smt node -------------- ");
        for (i, slot) in branch.iter().enumerate().take(2) {
            if let Some(child) = slot {
                // TODO: Seriously update `mpt_trie` to have a better API...
                let mut new_k = curr_key;
                new_k.push_nibble_back(i as Nibble);
                create_partial_trie_from_compact_node_rec(new_k, child, self)?;
            }
        }

        Ok(())
    }

    /// Adds the code to the `code_hash` --> `code_bytes` lookup. Only
    /// applicable to state tries.
    fn process_code(&mut self, c_bytes: Vec<u8>) -> CompactParsingResult<()>;

    // Nothing to do for empty nodes.
    fn process_empty(&self) -> CompactParsingResult<()> {
        Ok(())
    }

    /// Insert a hash node with our key that we constructed so far from
    /// traversing down the trie.
    fn process_hash(&mut self, curr_key: Nibbles, hash: TrieRootHash) -> CompactParsingResult<()> {
        self.trie().insert(curr_key, hash);

        Ok(())
    }

    /// Insert a value node with our key that we constructed so far from
    /// traversing down the trie.
    fn process_leaf(
        &mut self,
        curr_key: Nibbles,
        leaf_key: &Nibbles,
        leaf_node_data: &LeafNodeData,
    ) -> CompactParsingResult<()>;

    /// Appends the extension's key to our current key.
    fn process_extension(
        &mut self,
        curr_key: Nibbles,
        ext_node_key: &Nibbles,
        ext_child: &NodeEntry,
    ) -> CompactParsingResult<()> {
        let new_k = curr_key.merge_nibbles(ext_node_key);
        create_partial_trie_from_compact_node_rec(new_k, ext_child, self)?;

        Ok(())
    }

    /// Since we need to access the current trie for both concrete types, we
    /// need a common method to access the trie.
    fn trie(&mut self) -> &mut HashedPartialTrie;
}

#[derive(Debug)]
pub(super) enum UnexpectedCompactNodeType {
    AccountLeaf,
    Code,
}

/// Output from constructing a state trie from compact.
#[derive(Debug, Default)]
pub struct StateTrieExtractionOutput {
    /// The state trie of the compact.
    pub state_trie: HashedPartialTrie,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,

    /// All storage tries present in the compact.
    pub storage_tries: HashMap<HashedAccountAddr, HashedPartialTrie>,
}

impl CompactToPartialTrieExtractionOutput for StateTrieExtractionOutput {
    fn process_code(&mut self, c_bytes: Vec<u8>) -> CompactParsingResult<()> {
        let c_hash = hash(&c_bytes);
        self.code.insert(c_hash, c_bytes);

        Ok(())
    }

    fn process_leaf(
        &mut self,
        curr_key: Nibbles,
        leaf_key: &Nibbles,
        leaf_node_data: &LeafNodeData,
    ) -> CompactParsingResult<()> {
        process_leaf_common(
            &mut self.state_trie,
            curr_key,
            leaf_key,
            leaf_node_data,
            |acc_data, full_k| {
                Ok(process_account_node(
                    acc_data,
                    full_k,
                    &mut self.code,
                    &mut self.storage_tries,
                ))
            },
        )
    }

    fn trie(&mut self) -> &mut HashedPartialTrie {
        &mut self.state_trie
    }
}

/// Output from constructing a storage trie from mpt compact.
#[derive(Debug, Default)]
pub(super) struct StorageTrieExtractionOutput {
    pub(super) trie: HashedPartialTrie,
}

/// Output from constructing a storage trie from smt compact.
#[derive(Debug, Default)]
pub struct SmtStateTrieExtractionOutput {
    /// The state (and storage tries?) trie of the compact.
    pub state_smt: Vec<U256>,

    /// Any embedded contract bytecode that appears in the compact will be
    /// present here.
    pub code: HashMap<CodeHash, Vec<u8>>,
}

impl CompactToPartialTrieExtractionOutput for StorageTrieExtractionOutput {
    fn process_code(&mut self, c_bytes: Vec<u8>) -> CompactParsingResult<()> {
        Err(CompactParsingError::UnexpectedNodeForTrieType(
            UnexpectedCompactNodeType::Code,
            TrieType::Storage,
        ))
    }

    fn process_leaf(
        &mut self,
        curr_key: Nibbles,
        leaf_key: &Nibbles,
        leaf_node_data: &LeafNodeData,
    ) -> CompactParsingResult<()> {
        /// If we encounter an `AccountLeaf` when processing a storage trie,
        /// then something is wrong.
        process_leaf_common(
            &mut self.trie,
            curr_key,
            leaf_key,
            leaf_node_data,
            |_, _| {
                Err(CompactParsingError::UnexpectedNodeForTrieType(
                    UnexpectedCompactNodeType::AccountLeaf,
                    TrieType::Storage,
                ))
            },
        )
    }

    fn trie(&mut self) -> &mut HashedPartialTrie {
        &mut self.trie
    }
}

fn process_leaf_common<F: FnMut(&AccountNodeData, &Nibbles) -> CompactParsingResult<Vec<u8>>>(
    trie: &mut HashedPartialTrie,
    curr_key: Nibbles,
    leaf_key: &Nibbles,
    leaf_node_data: &LeafNodeData,
    mut account_leaf_proc_f: F,
) -> CompactParsingResult<()> {
    let full_k = curr_key.merge_nibbles(leaf_key);

    let l_val = match leaf_node_data {
        LeafNodeData::Value(v_bytes) => rlp::encode(&v_bytes.0).to_vec(),
        LeafNodeData::Account(acc_data) => account_leaf_proc_f(acc_data, &full_k)?,
    };

    trie.insert(full_k, l_val);
    Ok(())
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

pub(super) fn create_mpt_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<StateTrieExtractionOutput> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");

    create_mpt_trie_from_compact_node(remaining_node)
}

pub(super) fn create_storage_mpt_partial_trie_from_compact_node(
    node: NodeEntry,
) -> CompactParsingResult<StorageTrieExtractionOutput> {
    create_mpt_trie_from_compact_node(node)
}

fn create_mpt_trie_from_compact_node<T>(node: NodeEntry) -> CompactParsingResult<T>
where
    T: CompactToPartialTrieExtractionOutput + Default,
{
    let mut output = T::default();
    create_partial_trie_from_compact_node_rec(Nibbles::default(), &node, &mut output)?;

    Ok(output)
}

// TODO: Consider putting in some asserts that invalid nodes are not appearing
// in the wrong trie type (eg. account )
fn create_partial_trie_from_compact_node_rec<T>(
    curr_key: Nibbles,
    curr_node: &NodeEntry,
    output: &mut T,
) -> CompactParsingResult<()>
where
    T: CompactToPartialTrieExtractionOutput + ?Sized,
{
    trace!("Processing node {} into `PartialTrie` node...", curr_node);

    match curr_node {
        NodeEntry::BranchSMT(n) => output.process_branch_smt(curr_key, n),
        NodeEntry::Branch(n) => output.process_branch(curr_key, n),
        NodeEntry::Code(c_bytes) => output.process_code(c_bytes.clone()),
        NodeEntry::Empty => output.process_empty(),
        NodeEntry::Hash(h) => output.process_hash(curr_key, *h),
        NodeEntry::Leaf(k, v) => output.process_leaf(curr_key, k, v),
        NodeEntry::Extension(k, c) => output.process_extension(curr_key, k, c),
        NodeEntry::SMTLeaf(n, a, s, v) => output.process_empty(),
    }
}

fn process_account_node(
    acc_data: &AccountNodeData,
    h_addr_nibs: &HashedAccountAddrNibbles,
    c_hash_to_code: &mut HashMap<CodeHash, Vec<u8>>,
    h_addr_to_storage_trie: &mut HashMap<HashedAccountAddr, HashedPartialTrie>,
) -> Vec<u8> {
    let code_hash: keccak_hash::H256 = match &acc_data.account_node_code {
        Some(AccountNodeCode::CodeNode(c_bytes)) => {
            let c_hash = hash(c_bytes);
            c_hash_to_code.insert(c_hash, c_bytes.clone());

            c_hash
        }
        Some(AccountNodeCode::HashNode(c_hash)) => *c_hash,
        None => EMPTY_CODE_HASH,
    };

    let s_trie = acc_data.storage_trie.clone().unwrap_or_default().clone();
    let h_addr = HashedAccountAddr::from_slice(&h_addr_nibs.bytes_be());

    let storage_root = s_trie.hash();

    h_addr_to_storage_trie.insert(h_addr, s_trie);

    let account = MptAccountRlp {
        nonce: acc_data.nonce,
        balance: acc_data.balance,
        storage_root,
        code_hash,
    };

    // TODO: Avoid the unnecessary allocation...
    rlp::encode(&account).into()
}
