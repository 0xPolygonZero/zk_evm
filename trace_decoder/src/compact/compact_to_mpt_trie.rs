// TODO: Rename (or split) module as it's no longer just dealing specifically
// just with `HashedPartialTries`...

use std::{collections::HashMap, u8};

use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::generation::mpt::SMTLeafNodeRlp;
use log::trace;
use mpt_trie::{
    nibbles::{Nibble, Nibbles},
    partial_trie::{HashedPartialTrie, PartialTrie},
};

use super::compact_prestate_processing::{
    AccountNodeCode, AccountNodeData, CompactParsingResult, LeafNodeData, NodeEntry, WitnessEntry,
};
use crate::{
    compact::compact_prestate_processing::SMTLeafNode,
    types::{CodeHash, HashedAccountAddr, TrieRootHash, EMPTY_CODE_HASH, EMPTY_TRIE_HASH},
    utils::{h_addr_nibs_to_h256, hash},
};

#[derive(Debug, Default)]
pub(super) struct CompactToPartialTrieExtractionOutput {
    pub(super) trie: HashedPartialTrie,

    // TODO: `code` is ever only available for storage tries, so we should come up with a better
    // API that represents this...
    pub(super) code: HashMap<CodeHash, Vec<u8>>,
}

pub(super) fn create_partial_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<CompactToPartialTrieExtractionOutput> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");

    create_partial_trie_from_compact_node(remaining_node)
}

pub(super) fn create_partial_trie_from_compact_node(
    node: NodeEntry,
) -> CompactParsingResult<CompactToPartialTrieExtractionOutput> {
    let mut output = CompactToPartialTrieExtractionOutput::default();

    create_partial_trie_from_compact_node_rec(Nibbles::default(), &node, &mut output)?;

    Ok(output)
}

// TODO: Consider putting in some asserts that invalid nodes are not appearing
// in the wrong trie type (eg. account )
pub(super) fn create_partial_trie_from_compact_node_rec(
    curr_key: Nibbles,
    curr_node: &NodeEntry,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    trace!("Processing node {} into `PartialTrie` node...", curr_node);

    match curr_node {
        NodeEntry::BranchSMT(n) => process_branch_smt(curr_key, n, output),
        NodeEntry::Branch(n) => process_branch(curr_key, n, output),
        NodeEntry::Code(c_bytes) => process_code(c_bytes.clone(), output),
        NodeEntry::Empty => process_empty(),
        NodeEntry::Hash(h) => process_hash(curr_key, *h, &mut output.trie),
        NodeEntry::Leaf(k, v) => process_leaf(curr_key, k, v, output),
        NodeEntry::Extension(k, c) => process_extension(curr_key, k, c, output),
        NodeEntry::SMTLeaf(n, a, s, v) => process_smt_leaf(curr_key, n, a, s, v, output),
    }
}

fn process_branch(
    curr_key: Nibbles,
    branch: &[Option<Box<NodeEntry>>],
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    for (i, slot) in branch.iter().enumerate().take(16) {
        if let Some(child) = slot {
            // TODO: Seriously update `mpt_trie` to have a better API...
            let mut new_k = curr_key;
            new_k.push_nibble_back(i as Nibble);
            create_partial_trie_from_compact_node_rec(new_k, child, output)?;
        }
    }

    Ok(())
}

fn process_branch_smt(
    curr_key: Nibbles,
    branch: &[Option<Box<NodeEntry>>],
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    println!("-------------- branch smt node -------------- ");
    for (i, slot) in branch.iter().enumerate().take(2) {
        if let Some(child) = slot {
            let mut new_k = curr_key;
            new_k.push_nibble_back(i as Nibble);
            create_partial_trie_from_compact_node_rec(new_k, child, output)?;
        }
    }

    Ok(())
}

fn process_code(
    c_bytes: Vec<u8>,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    let c_hash = hash(&c_bytes);
    output.code.insert(c_hash, c_bytes);

    Ok(())
}

fn process_empty() -> CompactParsingResult<()> {
    println!("-------------- process empty -------------- ");
    // Nothing to do.
    Ok(())
}

fn process_smt_leaf(
    curr_key: Nibbles,
    n: &u8,
    a: &Vec<u8>,
    s: &Vec<u8>,
    v: &Vec<u8>,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    println!("-------------- process smt leaf -------------- ");

    // let smt_val = SMTLeafNodeRlp {
    //     address: a.clone(),
    //     storage_key: s.clone(),
    //     value: v.clone(),
    // };
    // output.trie.insert(curr_key, rlp::encode(&smt_val).into());

    // output.
    // TODO - Check if and key and value insertion are correct or not
    let mut new_k = curr_key;

    // for (i, b) in a.iter().enumerate() {
    //     new_k.push_nibble_back(i as Nibble);
    // }

    output.trie.insert(new_k, v.clone());
    Ok(())
}

fn process_hash(
    curr_key: Nibbles,
    hash: TrieRootHash,
    p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    println!("-------------- hash node -------------- ");
    // If we see a hash node at this stage, it must be a hashed out node in the
    // trie.
    p_trie.insert(curr_key, hash);

    Ok(())
}

fn process_leaf(
    curr_key: Nibbles,
    leaf_key: &Nibbles,
    leaf_node_data: &LeafNodeData,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    let full_k = curr_key.merge_nibbles(leaf_key);

    let l_val = match leaf_node_data {
        LeafNodeData::Value(v_bytes) => rlp::encode(&v_bytes.0).to_vec(),
        LeafNodeData::Account(acc_data) => {
            convert_account_node_data_to_rlp_bytes_and_add_any_code_to_lookup(acc_data, output)
        }
    };

    output.trie.insert(full_k, l_val);
    Ok(())
}

fn process_extension(
    curr_key: Nibbles,
    ext_node_key: &Nibbles,
    ext_child: &NodeEntry,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> CompactParsingResult<()> {
    println!("-------------- extension node -------------- ");
    let new_k = curr_key.merge_nibbles(ext_node_key);
    create_partial_trie_from_compact_node_rec(new_k, ext_child, output)?;

    Ok(())
}

fn convert_account_node_data_to_rlp_bytes_and_add_any_code_to_lookup(
    acc_data: &AccountNodeData,
    output: &mut CompactToPartialTrieExtractionOutput,
) -> Vec<u8> {
    let code_hash: keccak_hash::H256 = match &acc_data.account_node_code {
        Some(AccountNodeCode::CodeNode(c_bytes)) => {
            let c_hash = hash(c_bytes);
            output.code.insert(c_hash, c_bytes.clone());

            c_hash
        }
        Some(AccountNodeCode::HashNode(c_hash)) => *c_hash,
        None => EMPTY_CODE_HASH,
    };

    let account = AccountRlp {
        nonce: acc_data.nonce,
        balance: acc_data.balance,
        storage_root: acc_data.storage_root.unwrap_or(EMPTY_TRIE_HASH),
        code_hash,
    };

    // TODO: Avoid the unnecessary allocation...
    rlp::encode(&account).into()
}

pub(crate) fn convert_storage_trie_root_keyed_hashmap_to_account_addr_keyed(
    state_trie: &HashedPartialTrie,
    storage_root_trie: HashMap<TrieRootHash, HashedPartialTrie>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    let mut acc_addr_to_storage_trie_map = HashMap::new();

    let account_addr_and_storage_root_iter = state_trie.items()
        .filter_map(|(h_addr_nibs, acc_bytes)| {
            acc_bytes.as_val().map(|acc_bytes| {
                (h_addr_nibs_to_h256(&h_addr_nibs), rlp::decode::<AccountRlp>(acc_bytes).expect("Encoder lib managed to improperly encode an account node in the state trie! This is a major bug in the encoder.").storage_root)
        })
    });

    // TODO: Replace with a map...
    for (acc_addr, storage_root) in account_addr_and_storage_root_iter {
        if let Some(s_trie) = storage_root_trie.get(&storage_root) {
            // Possibility of identical tries between accounts, so we need to do a clone
            // here.
            acc_addr_to_storage_trie_map.insert(acc_addr, s_trie.clone());
        }
    }

    acc_addr_to_storage_trie_map
}
