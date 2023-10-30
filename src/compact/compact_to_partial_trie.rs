use std::collections::HashMap;

use eth_trie_utils::{
    nibbles::{Nibble, Nibbles},
    partial_trie::{HashedPartialTrie, PartialTrie},
};
use plonky2_evm::generation::mpt::AccountRlp;

use super::compact_prestate_processing::{
    AccountNodeCode, AccountNodeData, CompactParsingResult, LeafNodeData, NodeEntry, WitnessEntry,
};
use crate::{
    types::{CodeHash, EMPTY_CODE_HASH, EMPTY_TRIE_HASH},
    utils::hash,
};

#[derive(Debug, Default)]
pub(super) struct CompactToPartialOutput {
    pub(super) trie: HashedPartialTrie,

    // TODO: `code` is ever only available for storage tries, so we should come up with a better
    // API that represents this...
    pub(super) code: HashMap<CodeHash, Vec<u8>>,
}

pub(super) fn create_partial_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<CompactToPartialOutput> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");
    let mut output = CompactToPartialOutput::default();

    create_partial_trie_from_remaining_witness_elem_rec(
        Nibbles::default(),
        &remaining_node,
        &mut output,
    )?;

    Ok(output)
}

pub(super) fn create_partial_trie_from_remaining_witness_elem_rec(
    curr_key: Nibbles,
    curr_node: &NodeEntry,
    output: &mut CompactToPartialOutput,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::Account(_) => process_account(curr_key, curr_node, output),
        NodeEntry::Branch(n) => process_branch(curr_key, n, output),
        NodeEntry::Code(c_bytes) => process_code(c_bytes.clone(), output),
        NodeEntry::Empty => process_empty(curr_key, curr_node),
        NodeEntry::Hash(_) => process_hash(curr_key, curr_node, &mut output.trie),
        NodeEntry::Leaf(k, v) => process_leaf(curr_key, k, v, output),
        NodeEntry::Extension(k, c) => process_extension(curr_key, k, c, output),
    }
}

fn process_account(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _output: &mut CompactToPartialOutput,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_branch(
    curr_key: Nibbles,
    branch: &[Option<Box<NodeEntry>>],
    output: &mut CompactToPartialOutput,
) -> CompactParsingResult<()> {
    for i in 0..16 {
        if let Some(child) = &branch[i] {
            // TODO: Seriously update `eth_trie_utils` to have a better API...
            let mut new_k = curr_key;
            new_k.push_nibble_front(i as Nibble);
            create_partial_trie_from_remaining_witness_elem_rec(new_k, child, output)?;
        }
    }

    Ok(())
}

fn process_code(c_bytes: Vec<u8>, output: &mut CompactToPartialOutput) -> CompactParsingResult<()> {
    let c_hash = hash(&c_bytes);
    output.code.insert(c_hash, c_bytes);

    Ok(())
}

fn process_empty(_curr_key: Nibbles, _curr_node: &NodeEntry) -> CompactParsingResult<()> {
    todo!()
}

fn process_hash(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_leaf(
    curr_key: Nibbles,
    leaf_key: &Nibbles,
    leaf_node_data: &LeafNodeData,
    output: &mut CompactToPartialOutput,
) -> CompactParsingResult<()> {
    let full_k = curr_key.merge_nibbles(leaf_key);

    let l_val = match leaf_node_data {
        LeafNodeData::Value(v_bytes) => v_bytes.0.clone(),
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
    output: &mut CompactToPartialOutput,
) -> CompactParsingResult<()> {
    let new_k = curr_key.merge_nibbles(ext_node_key);
    create_partial_trie_from_remaining_witness_elem_rec(new_k, ext_child, output)?;

    Ok(())
}

fn process_value(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn convert_account_node_data_to_rlp_bytes_and_add_any_code_to_lookup(
    acc_data: &AccountNodeData,
    output: &mut CompactToPartialOutput,
) -> Vec<u8> {
    let code_hash = match &acc_data.account_node_code {
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
