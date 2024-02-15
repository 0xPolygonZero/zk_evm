//! A set of utility functions and constants to be used by `evm_arithmetization`
//! unit and integration tests.

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
};

pub use crate::cpu::kernel::cancun_constants::*;
use crate::{generation::mpt::AccountRlp, util::h2u};

pub const EMPTY_NODE_HASH: H256 = H256(hex!(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
));

pub fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

/// Converts a decimal string to a `U256`.
pub fn sd2u(s: &str) -> U256 {
    U256::from_dec_str(s).unwrap()
}

/// Converts an hexadecimal string to a `U256`.
pub fn sh2u(s: &str) -> U256 {
    U256::from_str_radix(s, 16).unwrap()
}

/// Inserts a new pair `(slot, value)` into the provided storage trie.
fn insert_storage(trie: &mut HashedPartialTrie, slot: U256, value: U256) {
    let mut bytes = [0; 32];
    slot.to_big_endian(&mut bytes);
    let key = keccak(bytes);
    let nibbles = Nibbles::from_bytes_be(key.as_bytes()).unwrap();
    let r = rlp::encode(&value);
    trie.insert(nibbles, r.freeze().to_vec());
}

/// Creates a storage trie for an account, given a list of `(slot, value)`
/// pairs.
pub fn create_account_storage(storage_pairs: &[(U256, U256)]) -> HashedPartialTrie {
    let mut trie = HashedPartialTrie::from(Node::Empty);
    for (slot, value) in storage_pairs {
        insert_storage(&mut trie, *slot, *value);
    }
    trie
}

/// Creates the storage trie of the beacon roots contract account at the
/// provided timestamp. Not passing any parent root will consider the parent
/// root at genesis, i.e. the empty hash.
fn beacon_roots_contract_storage(timestamp: U256, parent_root: H256) -> HashedPartialTrie {
    let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH.1;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.1;

    create_account_storage(&[(timestamp_idx, timestamp), (root_idx, h2u(parent_root))])
}

/// Updates the beacon roots account storage with the provided timestamp and
/// block parent root.
pub fn update_beacon_roots_account_storage(
    storage_trie: &mut HashedPartialTrie,
    timestamp: U256,
    parent_root: H256,
) {
    let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH.1;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.1;

    insert_storage(storage_trie, timestamp_idx, timestamp);
    insert_storage(storage_trie, root_idx, h2u(parent_root));
}

/// Returns the beacon roots contract account from its provided storage trie.
pub fn beacon_roots_contract_from_storage(storage_trie: &HashedPartialTrie) -> AccountRlp {
    AccountRlp {
        nonce: 0.into(),
        balance: 0.into(),
        storage_root: storage_trie.hash(),
        code_hash: H256(BEACON_ROOTS_CONTRACT_CODE_HASH),
    }
}

/// Returns an initial state trie containing nothing but the beacon roots
/// contract, along with its storage trie.
pub fn initial_state_and_storage_tries_with_beacon_roots(
) -> (HashedPartialTrie, Vec<(H256, HashedPartialTrie)>) {
    let state_trie = Node::Leaf {
        nibbles: Nibbles::from_bytes_be(&BEACON_ROOTS_CONTRACT_ADDRESS_HASHED).unwrap(),
        value: rlp::encode(&AccountRlp {
            nonce: 0.into(),
            balance: 0.into(),
            storage_root: EMPTY_NODE_HASH,
            code_hash: H256(BEACON_ROOTS_CONTRACT_CODE_HASH),
        })
        .to_vec(),
    }
    .into();

    let storage_tries = vec![(
        H256(BEACON_ROOTS_CONTRACT_ADDRESS_HASHED),
        Node::Empty.into(),
    )];

    (state_trie, storage_tries)
}

/// Returns the `Nibbles` corresponding to the beacon roots contract account.
pub fn beacon_roots_account_nibbles() -> Nibbles {
    Nibbles::from_bytes_be(&BEACON_ROOTS_CONTRACT_ADDRESS_HASHED).unwrap()
}

/// Converts an amount in `ETH` to `wei` units.
pub fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}
