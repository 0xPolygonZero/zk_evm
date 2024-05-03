use ethereum_types::H256;
use keccak_hash::keccak;
use log::trace;
use mpt_trie::{
    partial_trie::{HashedPartialTrie, PartialTrie},
    trie_ops::ValOrHash,
};

use crate::types::HashedStorageAddr;

pub(crate) fn hash(bytes: &[u8]) -> H256 {
    H256::from(keccak(bytes).0)
}

pub(crate) fn update_val_if_some<T>(target: &mut T, opt: Option<T>) {
    if let Some(new_val) = opt {
        *target = new_val;
    }
}

// TODO: Move under a feature flag...
pub(crate) fn print_value_and_hash_nodes_of_trie(trie: &HashedPartialTrie) {
    let trie_elems = print_value_and_hash_nodes_of_trie_common(trie);
    trace!("State trie {:#?}", trie_elems);
}

// TODO: Move under a feature flag...
pub(crate) fn print_value_and_hash_nodes_of_storage_trie(
    s_trie_addr: &HashedStorageAddr,
    trie: &HashedPartialTrie,
) {
    let trie_elems = print_value_and_hash_nodes_of_trie_common(trie);
    trace!("Storage trie for {:x}: {:#?}", s_trie_addr, trie_elems);
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

pub(crate) fn optional_field<T: std::fmt::Debug>(label: &str, value: Option<T>) -> String {
    value.map_or(String::new(), |v| format!("{}: {:?}\n", label, v))
}

pub(crate) fn optional_field_hex<T: std::fmt::UpperHex>(label: &str, value: Option<T>) -> String {
    value.map_or(String::new(), |v| format!("{}: 0x{:064X}\n", label, v))
}
