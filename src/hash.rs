use ethereum_types::H256;
use keccak_hash::keccak;

use crate::{bits::Bits, smt::RADIX, utils::u2b};

pub fn hash_leaf(rem_key: Bits, value: H256) -> H256 {
    let mut bytes = vec![];
    bytes.push(0); // Prefix for leaves
    bytes.extend(u2b(rem_key.packed));
    bytes.extend(value.0);
    keccak(bytes)
}

pub fn hash_internal(inner_hashes: [H256; RADIX]) -> H256 {
    let mut bytes = vec![];
    bytes.push(1); // Prefix for internal nodes
    for h in inner_hashes {
        bytes.extend(h.0);
    }
    keccak(bytes)
}
