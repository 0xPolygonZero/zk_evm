use std::{
    collections::HashMap,
    fmt::{self, Display},
};

use evm_arithmetization::generation::mpt::AccountRlp;
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
    decoding::TrieType,
    types::{
        CodeHash, HashedAccountAddr, HashedAccountAddrNibbles, TrieRootHash, EMPTY_CODE_HASH,
        EMPTY_TRIE_HASH,
    },
    utils::{h_addr_nibs_to_h256, hash},
};

pub trait CompactToPartialTrieExtractionOutput {
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

    fn process_code(&mut self, c_bytes: Vec<u8>) -> CompactParsingResult<()>;

    fn process_empty(&self) -> CompactParsingResult<()> {
        // Nothing to do.
        Ok(())
    }

    fn process_hash(&mut self, curr_key: Nibbles, hash: TrieRootHash) -> CompactParsingResult<()> {
        self.get_trie().insert(curr_key, hash);

        Ok(())
    }

    fn process_leaf(
        &mut self,
        curr_key: Nibbles,
        leaf_key: &Nibbles,
        leaf_node_data: &LeafNodeData,
    ) -> CompactParsingResult<()>;

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

    fn get_trie(&mut self) -> &mut HashedPartialTrie;
}

#[derive(Debug)]
pub(super) enum UnexpectedCompactNodeType {
    AccountLeaf,
    Code,
}

impl Display for UnexpectedCompactNodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnexpectedCompactNodeType::AccountLeaf => write!(f, "AccountLeaf"),
            UnexpectedCompactNodeType::Code => write!(f, "Code"),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct StateTrieExtractionOutput {
    pub(super) trie: HashedPartialTrie,
    pub(super) code: HashMap<CodeHash, Vec<u8>>,
    pub(super) storage_tries: HashMap<HashedAccountAddr, HashedPartialTrie>,
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
            &mut self.trie,
            curr_key,
            leaf_key,
            leaf_node_data,
            |acc_data, full_k| {
                Ok(
                    convert_account_node_data_to_rlp_bytes_and_add_any_code_to_lookup(
                        acc_data,
                        full_k,
                        &mut self.code,
                        &mut self.storage_tries,
                    ),
                )
            },
        )
    }

    fn get_trie(&mut self) -> &mut HashedPartialTrie {
        &mut self.trie
    }
}
#[derive(Debug, Default)]
pub(super) struct StorageTrieExtractionOutput {
    pub(super) trie: HashedPartialTrie,
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

    fn get_trie(&mut self) -> &mut HashedPartialTrie {
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

pub(super) fn create_partial_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<StateTrieExtractionOutput> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");

    create_partial_trie_from_compact_node(remaining_node)
}

pub(super) fn create_storage_partial_trie_from_compact_node(
    node: NodeEntry,
) -> CompactParsingResult<StorageTrieExtractionOutput> {
    create_partial_trie_from_compact_node(node)
}

fn create_partial_trie_from_compact_node<T: CompactToPartialTrieExtractionOutput + Default>(
    node: NodeEntry,
) -> CompactParsingResult<T> {
    let mut output = T::default();
    create_partial_trie_from_compact_node_rec(Nibbles::default(), &node, &mut output)?;

    Ok(output)
}

// TODO: Consider putting in some asserts that invalid nodes are not appearing
// in the wrong trie type (eg. account )
pub(super) fn create_partial_trie_from_compact_node_rec<
    T: CompactToPartialTrieExtractionOutput + ?Sized,
>(
    curr_key: Nibbles,
    curr_node: &NodeEntry,
    output: &mut T,
) -> CompactParsingResult<()> {
    trace!("Processing node {} into `PartialTrie` node...", curr_node);

    match curr_node {
        NodeEntry::Branch(n) => output.process_branch(curr_key, n),
        NodeEntry::Code(c_bytes) => output.process_code(c_bytes.clone()),
        NodeEntry::Empty => output.process_empty(),
        NodeEntry::Hash(h) => output.process_hash(curr_key, *h),
        NodeEntry::Leaf(k, v) => output.process_leaf(curr_key, k, v),
        NodeEntry::Extension(k, c) => output.process_extension(curr_key, k, c),
    }
}

fn convert_account_node_data_to_rlp_bytes_and_add_any_code_to_lookup(
    acc_data: &AccountNodeData,
    h_addr_nibs: &HashedAccountAddrNibbles,
    c_hash_to_code: &mut HashMap<CodeHash, Vec<u8>>,
    h_addr_to_storage_trie: &mut HashMap<HashedAccountAddr, HashedPartialTrie>,
) -> Vec<u8> {
    let code_hash = match &acc_data.account_node_code {
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

    let account = AccountRlp {
        nonce: acc_data.nonce,
        balance: acc_data.balance,
        storage_root,
        code_hash,
    };

    // TODO: Avoid the unnecessary allocation...
    rlp::encode(&account).into()
}
