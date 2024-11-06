use alloy::primitives::U256;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::Poseidon;

use crate::smt::{HashOut, Key, Node, F};

/// Returns `Poseidon(x, [0,0,0,0])`.
pub(crate) fn hash0(x: [F; 8]) -> [F; 4] {
    F::poseidon(std::array::from_fn(|i| if i < 8 { x[i] } else { F::ZERO }))[0..4]
        .try_into()
        .unwrap()
}

/// Returns `Poseidon(x, [1,0,0,0])`.
pub(crate) fn hash1(x: [F; 8]) -> [F; 4] {
    F::poseidon(std::array::from_fn(|i| match i {
        j if j < 8 => x[i],
        8 => F::ONE,
        _ => F::ZERO,
    }))[0..4]
        .try_into()
        .unwrap()
}

/// Returns `Poseidon(key || h, [1,0,0,0])`.
pub(crate) fn hash_key_hash(k: Key, h: [F; 4]) -> [F; 4] {
    hash1(std::array::from_fn(
        |i| if i < 4 { k.0[i] } else { h[i - 4] },
    ))
}

/// Split a U256 into 8 32-bit limbs in little-endian order.
pub(crate) fn f2limbs(x: U256) -> [F; 8] {
    std::array::from_fn(|i| {
        let x = *(x >> (32 * i)).as_limbs().first().unwrap();
        F::from_canonical_u32(x as u32)
    })
}

/// Pack 8 32-bit limbs in little-endian order into a U256.
pub(crate) fn limbs2f(limbs: [F; 8]) -> U256 {
    limbs
        .into_iter()
        .enumerate()
        .fold(U256::ZERO, |acc, (i, x)| {
            acc + (U256::from(x.to_canonical_u64()) << (i * 32))
        })
}

/// Convert a `HashOut` to a `U256`.
pub fn hashout2u(h: HashOut) -> U256 {
    key2u(Key(h.elements))
}

/// Convert a `HashOut` to a `H256`.
pub fn hashout2h(h: HashOut) -> H256 {
    let mut it = [0; 32];
    hashout2u(h).to_big_endian(&mut it);
    H256(it)
}

/// Convert a `Key` to a `U256`.
pub fn key2u(key: Key) -> U256 {
    U256::from_limbs(key.0.map(|x| x.to_canonical_u64()))
}

/// Convert a `U256` to a `Hashout`.
pub(crate) fn u2h(x: U256) -> HashOut {
    HashOut {
        elements: x.as_limbs().map(F::from_canonical_u64),
    }
}

/// Convert a `U256` to a `Key`.
pub(crate) fn u2k(x: U256) -> Key {
    Key(x.as_limbs().map(F::from_canonical_u64))
}

/// Given a node, return the index of the unique non-zero sibling, or -1 if
/// there is no such sibling.
pub(crate) fn get_unique_sibling(node: Node) -> isize {
    let mut nfound = 0;
    let mut fnd = 0;
    for i in (0..12).step_by(4) {
        if !(node.0[i].is_zero()
            && node.0[i + 1].is_zero()
            && node.0[i + 2].is_zero()
            && node.0[i + 3].is_zero())
        {
            nfound += 1;
            fnd = i as isize / 4;
        }
    }
    if nfound == 1 {
        fnd
    } else {
        -1
    }
}
