//! A set of utility functions and constants to be used by `evm_arithmetization`
//! unit and integration tests.

use std::collections::HashMap;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, H160, H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use smt_trie::{
    db::{Db, MemoryDb},
    keys::{key_balance, key_code, key_code_length, key_nonce, key_storage},
    smt::Smt,
};

pub use crate::cpu::kernel::cancun_constants::*;
pub use crate::cpu::kernel::constants::global_exit_root::{
    GLOBAL_EXIT_ROOT_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_STORAGE_POS,
};
use crate::{
    cpu::kernel::global_exit_root::{
        global_exit_root_account, GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY,
    },
    generation::mpt::AccountRlp,
    proof::BlockMetadata,
    util::h2u,
};

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
fn insert_storage<D: Db>(smt: &mut Smt<D>, addr: Address, slot: U256, value: U256) {
    smt.set(key_storage(addr, slot), value);
}

/// Updates the beacon roots account storage with the provided timestamp and
/// block parent root.
pub fn update_beacon_roots_account_storage(
    state_smt: &mut Smt<MemoryDb>,
    timestamp: U256,
    parent_root: H256,
) {
    let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH.1;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.1;

    insert_storage(
        state_smt,
        H160(BEACON_ROOTS_CONTRACT_STATE_KEY.1),
        timestamp_idx,
        timestamp,
    );
    insert_storage(
        state_smt,
        H160(BEACON_ROOTS_CONTRACT_STATE_KEY.1),
        root_idx,
        h2u(parent_root),
    );
}

/// Calculates the beacon roots account storage with the provided timestamp and
/// block parent root.
pub fn compute_beacon_roots_account_storage(
    timestamp: U256,
    parent_root: H256,
) -> HashMap<U256, U256> {
    let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH.1;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.1;

    HashMap::from([(timestamp_idx, timestamp), (root_idx, h2u(parent_root))])
}

/// Returns an initial state trie containing the beacon roots and global exit
/// roots contracts, along with their storage tries.
pub fn preinitialized_state() -> Smt<MemoryDb> {
    let mut smt = Smt::<MemoryDb>::default();
    set_beacon_roots_account(&mut smt, &HashMap::new());
    set_global_exit_root_account(&mut smt, &HashMap::new());

    smt
}

/// Returns a final state trie containing the beacon roots and global exit
/// roots contracts, with their updated storage.
pub fn preinitialized_state_with_updated_storage(
    block: &BlockMetadata,
    global_exit_roots: &[(U256, H256)],
) -> Smt<MemoryDb> {
    let mut smt = Smt::<MemoryDb>::default();
    let beacon_roots_storage =
        compute_beacon_roots_account_storage(block.block_timestamp, block.parent_beacon_block_root);
    set_beacon_roots_account(&mut smt, &beacon_roots_storage);

    let mut storage = HashMap::new();
    for &(timestamp, root) in global_exit_roots {
        storage.insert(ger_storage_slot(root), timestamp);
    }
    set_global_exit_root_account(&mut smt, &storage);

    smt
}

fn ger_storage_slot(root: H256) -> U256 {
    let mut arr = [0; 64];
    arr[0..32].copy_from_slice(&root.0);
    U256::from(GLOBAL_EXIT_ROOT_STORAGE_POS.1).to_big_endian(&mut arr[32..64]);
    let slot = keccak(arr);
    h2u(slot)
}

pub fn update_ger_account_storage(state_smt: &mut Smt<MemoryDb>, root: H256, timestamp: U256) {
    insert_storage(
        state_smt,
        H160(GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY.1),
        ger_storage_slot(root),
        timestamp,
    );
}

/// Converts an amount in `ETH` to `wei` units.
pub fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

pub fn set_account<D: Db>(
    smt: &mut Smt<D>,
    addr: Address,
    account: &AccountRlp,
    storage: &HashMap<U256, U256>,
) {
    smt.set(key_balance(addr), account.balance);
    smt.set(key_nonce(addr), account.nonce);
    smt.set(key_code(addr), account.code_hash);
    smt.set(key_code_length(addr), account.code_length);
    for (&k, &v) in storage {
        smt.set(key_storage(addr, k), v);
    }
}

pub fn set_beacon_roots_account<D: Db>(smt: &mut Smt<D>, storage: &HashMap<U256, U256>) {
    set_account(
        smt,
        H160(BEACON_ROOTS_CONTRACT_STATE_KEY.1),
        &beacon_roots_account(),
        storage,
    );
}

pub fn set_global_exit_root_account<D: Db>(smt: &mut Smt<D>, storage: &HashMap<U256, U256>) {
    set_account(
        smt,
        H160(GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY.1),
        &global_exit_root_account(),
        storage,
    );
}
