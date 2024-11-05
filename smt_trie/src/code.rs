/// Functions to hash contract bytecode using Poseidon.
/// See `hashContractBytecode()` in https://github.com/0xPolygonHermez/zkevm-commonjs/blob/main/src/smt-utils.js for reference implementation.
use alloy::primitives::U256;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::{self, Poseidon};

use crate::smt::{HashOut, F};
use crate::utils::hashout2h;

pub fn hash_contract_bytecode(mut code: Vec<u8>) -> HashOut {
    poseidon_pad_byte_vec(&mut code);

    poseidon_hash_padded_byte_vec(code)
}

pub fn poseidon_hash_padded_byte_vec(bytes: Vec<u8>) -> HashOut {
    let mut capacity = [F::ZERO; poseidon::SPONGE_CAPACITY];
    let mut arr = [F::ZERO; poseidon::SPONGE_WIDTH];
    for blocks in bytes.chunks_exact(poseidon::SPONGE_RATE * 7) {
        arr[..poseidon::SPONGE_RATE].copy_from_slice(
            &blocks
                .chunks_exact(7)
                .map(|block| {
                    let mut bytes = [0u8; poseidon::SPONGE_RATE];
                    bytes[..7].copy_from_slice(block);
                    F::from_canonical_u64(u64::from_le_bytes(bytes))
                })
                .collect::<Vec<F>>(),
        );
        arr[poseidon::SPONGE_RATE..poseidon::SPONGE_WIDTH].copy_from_slice(&capacity);
        capacity = F::poseidon(arr)[0..poseidon::SPONGE_CAPACITY]
            .try_into()
            .unwrap();
    }
    HashOut { elements: capacity }
}

pub fn poseidon_pad_byte_vec(bytes: &mut Vec<u8>) {
    bytes.push(0x01);
    while bytes.len() % 56 != 0 {
        bytes.push(0x00);
    }
    *bytes.last_mut().unwrap() |= 0x80;
}

pub fn hash_bytecode_h256(code: &[u8]) -> H256 {
    hashout2h(hash_contract_bytecode(code.to_vec()))
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_empty_code() {
        assert_eq!(
            hash_contract_bytecode(vec![]).elements,
            [
                10052403398432742521,
                15195891732843337299,
                2019258788108304834,
                4300613462594703212,
            ]
            .map(F::from_canonical_u64)
        );
    }

    #[test]
    fn test_some_code() {
        let code = hex!("60806040526004361061003f5760003560e01c80632b68b9c6146100445780633fa4f2451461005b5780635cfb28e714610086578063718da7ee14610090575b600080fd5b34801561005057600080fd5b506100596100b9565b005b34801561006757600080fd5b506100706100f2565b60405161007d9190610195565b60405180910390f35b61008e6100f8565b005b34801561009c57600080fd5b506100b760048036038101906100b29190610159565b610101565b005b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16ff5b60015481565b34600181905550565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050565b600081359050610153816101f1565b92915050565b60006020828403121561016f5761016e6101ec565b5b600061017d84828501610144565b91505092915050565b61018f816101e2565b82525050565b60006020820190506101aa6000830184610186565b92915050565b60006101bb826101c2565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600080fd5b6101fa816101b0565b811461020557600080fd5b5056fea26469706673582212207ae6e5d5feddef608b24cca98990c37cf78f8b377163a7c4951a429d90d6120464736f6c63430008070033");

        assert_eq!(
            hash_contract_bytecode(code.to_vec()).elements,
            [
                13311281292453978464,
                8384462470517067887,
                14733964407220681187,
                13541155386998871195
            ]
            .map(F::from_canonical_u64)
        );
    }
}
