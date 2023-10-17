use ethereum_types::{H256, U256};
use keccak_hash::keccak;

use crate::{bits::Bits, smt::RADIX};

fn u2b(x: U256) -> [u8; 32] {
    let mut res = [0; 32];
    x.to_big_endian(&mut res);
    res
}

pub fn hash_leaf(key: Bits, value: &[u8]) -> H256 {
    let mut bytes = vec![];
    bytes.push(0); // Prefix for leaves
    assert_eq!(key.count, 256);
    bytes.extend(u2b(key.packed));
    bytes.extend(value);
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
