use ethereum_types::U256;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::Poseidon;

use crate::smt::{HashOut, Key, F};

pub(crate) fn hash0(x: [F; 8]) -> [F; 4] {
    F::poseidon(std::array::from_fn(|i| if i < 8 { x[i] } else { F::ZERO }))[0..4]
        .try_into()
        .unwrap()
}

pub(crate) fn hash1(x: [F; 8]) -> [F; 4] {
    F::poseidon(std::array::from_fn(|i| match i {
        j if j < 8 => x[i],
        8 => F::ONE,
        _ => F::ZERO,
    }))[0..4]
        .try_into()
        .unwrap()
}

pub(crate) fn hash_key_hash(k: Key, h: [F; 4]) -> [F; 4] {
    hash1(std::array::from_fn(
        |i| if i < 4 { k.0[i] } else { h[i - 4] },
    ))
}

pub(crate) fn f2limbs(x: U256) -> [F; 8] {
    std::array::from_fn(|i| F::from_canonical_u32((x >> (32 * i)).low_u32()))
}

pub(crate) fn limbs2f(limbs: [F; 8]) -> U256 {
    limbs
        .into_iter()
        .enumerate()
        .fold(U256::zero(), |acc, (i, x)| {
            acc + (U256::from(x.to_canonical_u64()) << (i * 32))
        })
}

pub fn hashout2u(h: HashOut) -> U256 {
    key2u(Key(h.elements))
}
pub(crate) fn key2u(key: Key) -> U256 {
    U256(key.0.map(|x| x.to_canonical_u64()))
}

pub(crate) fn u2h(x: U256) -> HashOut {
    HashOut {
        elements: x.0.map(F::from_canonical_u64),
    }
}

pub(crate) fn u2k(x: U256) -> Key {
    Key(x.0.map(F::from_canonical_u64))
}
