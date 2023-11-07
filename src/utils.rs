use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
    trie_ops::ValOrHash,
};
use ethereum_types::H256;
use keccak_hash::keccak;

use crate::types::HashedStorageAddr;

pub(crate) fn hash(bytes: &[u8]) -> H256 {
    H256::from(keccak(bytes).0)
}

pub(crate) fn update_val_if_some<T>(target: &mut T, opt: Option<T>) {
    if let Some(new_val) = opt {
        *target = new_val;
    }
}

pub(crate) fn clone_vec_and_remove_refs<T: Clone>(vec_of_refs: &[&T]) -> Vec<T> {
    vec_of_refs.iter().map(|r| (*r).clone()).collect()
}

pub(crate) fn h256_to_nibbles(v: H256) -> Nibbles {
    Nibbles::from_h256_be(v)
}

// TODO: Move under a feature flag...
pub(crate) fn print_value_and_hash_nodes_of_trie(trie: &HashedPartialTrie) {
    let trie_elems = print_value_and_hash_nodes_of_trie_common(trie);
    println!("State trie {:#?}", trie_elems);
}

// TODO: Move under a feature flag...
pub(crate) fn print_value_and_hash_nodes_of_storage_trie(
    s_trie_addr: &HashedStorageAddr,
    trie: &HashedPartialTrie,
) {
    let trie_elems = print_value_and_hash_nodes_of_trie_common(trie);
    println!("Storage trie for {:x}: {:#?}", s_trie_addr, trie_elems);
}

// TODO: Move under a feature flag...
fn print_value_and_hash_nodes_of_trie_common(trie: &HashedPartialTrie) -> Vec<String> {
    trie.items()
        .map(|(k, v_or_h)| {
            let v_or_h_char = match v_or_h {
                ValOrHash::Val(_) => 'L',
                ValOrHash::Hash(_) => 'H',
            };
            format!("{} - {:x}", v_or_h_char, k)
        })
        .collect()
}
