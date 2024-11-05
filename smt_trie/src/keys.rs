#![allow(clippy::needless_range_loop)]

/// This module contains functions to generate keys for the SMT.
/// See https://github.com/0xPolygonHermez/zkevm-commonjs/blob/main/src/smt-utils.js for reference implementation.
use alloy::primitives::{Address, U256};
use plonky2::{field::types::Field, hash::poseidon::Poseidon};

use crate::smt::{Key, F};

const HASH_ZEROS: [u64; 4] = [
    4330397376401421145,
    14124799381142128323,
    8742572140681234676,
    14345658006221440202,
];

const SMT_KEY_BALANCE: u64 = 0;
const SMT_KEY_NONCE: u64 = 1;
const SMT_KEY_CODE: u64 = 2;
const SMT_KEY_STORAGE: u64 = 3;
const SMT_KEY_LENGTH: u64 = 4;

pub fn key_balance(addr: Address) -> Key {
    let mut arr = [F::ZERO; 12];
    for i in 0..5 {
        arr[i] = F::from_canonical_u32(u32::from_be_bytes(
            addr.0[16 - 4 * i..16 - 4 * i + 4].try_into().unwrap(),
        ));
    }

    arr[6] = F::from_canonical_u64(SMT_KEY_BALANCE);
    arr[8..12].copy_from_slice(&HASH_ZEROS.map(F::from_canonical_u64));

    Key(F::poseidon(arr)[0..4].try_into().unwrap())
}

pub fn key_nonce(addr: Address) -> Key {
    let mut arr = [F::ZERO; 12];
    for i in 0..5 {
        arr[i] = F::from_canonical_u32(u32::from_be_bytes(
            addr.0[16 - 4 * i..16 - 4 * i + 4].try_into().unwrap(),
        ));
    }

    arr[6] = F::from_canonical_u64(SMT_KEY_NONCE);
    arr[8..12].copy_from_slice(&HASH_ZEROS.map(F::from_canonical_u64));

    Key(F::poseidon(arr)[0..4].try_into().unwrap())
}

pub fn key_code(addr: Address) -> Key {
    let mut arr = [F::ZERO; 12];
    for i in 0..5 {
        arr[i] = F::from_canonical_u32(u32::from_be_bytes(
            addr.0[16 - 4 * i..16 - 4 * i + 4].try_into().unwrap(),
        ));
    }

    arr[6] = F::from_canonical_u64(SMT_KEY_CODE);
    arr[8..12].copy_from_slice(&HASH_ZEROS.map(F::from_canonical_u64));

    Key(F::poseidon(arr)[0..4].try_into().unwrap())
}

pub fn key_storage(addr: Address, slot: U256) -> Key {
    let mut arr = [F::ZERO; 12];
    for i in 0..5 {
        arr[i] = F::from_canonical_u32(u32::from_be_bytes(
            addr.0[16 - 4 * i..16 - 4 * i + 4].try_into().unwrap(),
        ));
    }

    arr[6] = F::from_canonical_u64(SMT_KEY_STORAGE);
    let capacity: [F; 4] = {
        let mut arr = [F::ZERO; 12];
        for i in 0..4 {
            arr[2 * i] = F::from_canonical_u32(u32::try_from(slot).unwrap());
            arr[2 * i + 1] = F::from_canonical_u32((u64::try_from(slot).unwrap() >> 32) as u32);
        }
        F::poseidon(arr)[0..4].try_into().unwrap()
    };
    arr[8..12].copy_from_slice(&capacity);

    Key(F::poseidon(arr)[0..4].try_into().unwrap())
}

pub fn key_code_length(addr: Address) -> Key {
    let mut arr = [F::ZERO; 12];
    for i in 0..5 {
        arr[i] = F::from_canonical_u32(u32::from_be_bytes(
            addr.0[16 - 4 * i..16 - 4 * i + 4].try_into().unwrap(),
        ));
    }

    arr[6] = F::from_canonical_u64(SMT_KEY_LENGTH);
    arr[8..12].copy_from_slice(&HASH_ZEROS.map(F::from_canonical_u64));

    Key(F::poseidon(arr)[0..4].try_into().unwrap())
}
