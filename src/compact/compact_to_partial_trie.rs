use eth_trie_utils::{nibbles::Nibbles, partial_trie::HashedPartialTrie};

use super::compact_prestate_processing::{CompactParsingResult, NodeEntry, WitnessEntry};

pub(super) fn create_partial_trie_from_remaining_witness_elem(
    remaining_entry: WitnessEntry,
) -> CompactParsingResult<HashedPartialTrie> {
    let remaining_node = remaining_entry
        .into_node()
        .expect("Final node in compact entries was not a node! This is a bug!");
    let mut trie = HashedPartialTrie::default();

    create_partial_trie_from_remaining_witness_elem_rec(
        Nibbles::default(),
        &remaining_node,
        &mut trie,
    )?;

    Ok(trie)
}

pub(super) fn create_partial_trie_from_remaining_witness_elem_rec(
    curr_key: Nibbles,
    curr_node: &NodeEntry,
    p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::Account(_) => process_account(curr_key, curr_node, p_trie),
        NodeEntry::Branch(_) => process_branch(curr_key, curr_node, p_trie),
        NodeEntry::Code(_) => process_code(curr_key, curr_node, p_trie),
        NodeEntry::Empty => process_empty(curr_key, curr_node, p_trie),
        NodeEntry::Hash(_) => process_hash(curr_key, curr_node, p_trie),
        NodeEntry::Leaf(_, _) => process_leaf(curr_key, curr_node, p_trie),
        NodeEntry::Extension(_, _) => process_extension(curr_key, curr_node, p_trie),
        NodeEntry::Value(_) => process_value(curr_key, curr_node, p_trie),
    }
}

fn process_account(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_branch(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_code(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_empty(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
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
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_extension(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}

fn process_value(
    _curr_key: Nibbles,
    _curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    todo!()
}
