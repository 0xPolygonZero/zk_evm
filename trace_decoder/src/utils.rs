use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use log::trace;

use crate::{aliased_crate_types::{HashedPartialTrie, Nibbles, PartialTrie, ValOrHash}, types::StorageAddr};
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

/// Converts `[`Nibbles`]` to an [`H256`].
///
/// Note that this is meant to only be called on Nibbles that have all 64
/// internal nibbles set, and will error if not all of them are used.
pub(crate) fn nibbles_to_h256(n: &Nibbles) -> H256 {
    // TODO: Have this return a `Result`...
    assert!(
        n.count >= 64,
        "Attempted to create an H256 from `Nibbles` that had less than 64 nibbles!"
    );

    H256::from_slice(&n.bytes_be())
}

pub(crate) fn nibbles_to_u256(n: &Nibbles) -> U256 {
    U256::from_big_endian(&n.bytes_be())
}

pub(crate) fn is_rlped_0(v: &U256) -> bool {
    v.as_u64() == 128
}

pub(crate) fn u256_to_bytes(v: &U256) -> [u8; 32] {
    let mut buf: [u8; 32] = [0; 32];
    v.to_big_endian(&mut buf);

    buf
}

pub(crate) fn u256_to_h256(v: &U256) -> H256 {
    let mut h256 = H256::zero();
    v.to_big_endian(&mut h256.0);

    h256
}

/// Hash an address and convert the hash to [Nibbles].
pub(crate) fn hash_addr_to_nibbles(v: &Address) -> Nibbles {
    Nibbles::from_h256_be(hash(v.as_bytes()))
}

pub(crate) fn hash_slot_to_nibbles(v: &StorageAddr) -> Nibbles {
    Nibbles::from_h256_be(hash(&u256_to_bytes(v)))
}
