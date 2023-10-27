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
    _curr_key: Nibbles,
    curr_node: &NodeEntry,
    _p_trie: &mut HashedPartialTrie,
) -> CompactParsingResult<()> {
    match curr_node {
        NodeEntry::Account(_) => todo!(),
        NodeEntry::Branch(_) => todo!(),
        NodeEntry::Code(_) => todo!(),
        NodeEntry::Empty => todo!(),
        NodeEntry::Hash(_) => todo!(),
        NodeEntry::Leaf(_, _) => todo!(),
        NodeEntry::Extension(_, _) => todo!(),
        NodeEntry::Value(_) => todo!(),
    }
}
