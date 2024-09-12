//! A set of utility functions and constants to be used by `evm_arithmetization`
//! unit and integration tests.

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{BigEndianHash, H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
};

pub use crate::cpu::kernel::cancun_constants::*;
pub use crate::cpu::kernel::constants::global_exit_root::*;
use crate::{generation::mpt::AccountRlp, proof::BlockMetadata, util::h2u};

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
fn insert_storage(trie: &mut HashedPartialTrie, slot: U256, value: U256) -> anyhow::Result<()> {
    let mut bytes = [0; 32];
    slot.to_big_endian(&mut bytes);
    let key = keccak(bytes);
    let nibbles = Nibbles::from_bytes_be(key.as_bytes()).unwrap();
    if value.is_zero() {
        trie.delete(nibbles)?;
    } else {
        let r = rlp::encode(&value);
        trie.insert(nibbles, r.freeze().to_vec())?;
    }
    Ok(())
}

/// Creates a storage trie for an account, given a list of `(slot, value)`
/// pairs.
pub fn create_account_storage(storage_pairs: &[(U256, U256)]) -> anyhow::Result<HashedPartialTrie> {
    let mut trie = HashedPartialTrie::from(Node::Empty);
    for (slot, value) in storage_pairs {
        insert_storage(&mut trie, *slot, *value)?;
    }
    Ok(trie)
}

/// Updates the beacon roots account storage with the provided timestamp and
/// block parent root.
pub fn update_beacon_roots_account_storage(
    storage_trie: &mut HashedPartialTrie,
    timestamp: U256,
    parent_root: H256,
) -> anyhow::Result<()> {
    let timestamp_idx = timestamp % HISTORY_BUFFER_LENGTH.value;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.value;

    insert_storage(storage_trie, timestamp_idx, timestamp)?;
    insert_storage(storage_trie, root_idx, h2u(parent_root))
}

/// Returns the beacon roots contract account from its provided storage trie.
pub fn beacon_roots_contract_from_storage(storage_trie: &HashedPartialTrie) -> AccountRlp {
    AccountRlp {
        storage_root: storage_trie.hash(),
        ..BEACON_ROOTS_ACCOUNT
    }
}

/// Returns an initial state trie containing the beacon roots and global exit
/// roots contracts, along with their storage tries.
pub fn preinitialized_state_and_storage_tries(
) -> anyhow::Result<(HashedPartialTrie, Vec<(H256, HashedPartialTrie)>)> {
    let mut state_trie = HashedPartialTrie::from(Node::Empty);
    state_trie.insert(
        beacon_roots_account_nibbles(),
        rlp::encode(&BEACON_ROOTS_ACCOUNT).to_vec(),
    )?;

    let storage_tries = vec![(BEACON_ROOTS_CONTRACT_ADDRESS_HASHED, Node::Empty.into())];

    Ok((state_trie, storage_tries))
}

/// Returns the `Nibbles` corresponding to the beacon roots contract account.
pub fn beacon_roots_account_nibbles() -> Nibbles {
    Nibbles::from_bytes_be(BEACON_ROOTS_CONTRACT_ADDRESS_HASHED.as_bytes()).unwrap()
}

/// Returns the `Nibbles` corresponding to the GER manager account.
pub fn ger_account_nibbles() -> Nibbles {
    Nibbles::from_bytes_be(GLOBAL_EXIT_ROOT_ADDRESS_HASHED.as_bytes()).unwrap()
}

pub fn update_ger_account_storage(
    storage_trie: &mut HashedPartialTrie,
    ger_data: Option<(H256, H256)>,
) -> anyhow::Result<()> {
    if let Some((root, l1blockhash)) = ger_data {
        let mut arr = [0; 64];
        arr[0..32].copy_from_slice(&root.0);
        U256::from(GLOBAL_EXIT_ROOT_STORAGE_POS.1).to_big_endian(&mut arr[32..64]);
        let slot = keccak(arr);
        insert_storage(storage_trie, slot.into_uint(), h2u(l1blockhash))?
    }

    Ok(())
}

/// Returns the `Nibbles` corresponding to the 5ca1ab1e contract account.
pub fn scalable_account_nibbles() -> Nibbles {
    Nibbles::from_bytes_be(ADDRESS_SCALABLE_L2_ADDRESS_HASHED.as_bytes()).unwrap()
}

/// Note: This *will* overwrite the timestamp stored at the contract address.
pub fn update_scalable_account_storage(
    storage_trie: &mut HashedPartialTrie,
    block: &BlockMetadata,
    initial_trie_hash: H256,
) -> anyhow::Result<()> {
    insert_storage(
        storage_trie,
        U256::from(LAST_BLOCK_STORAGE_POS.1),
        block.block_number,
    )?;
    insert_storage(
        storage_trie,
        U256::from(TIMESTAMP_STORAGE_POS.1),
        block.block_timestamp,
    )?;

    let mut arr = [0; 64];
    (block.block_number - U256::one()).to_big_endian(&mut arr[0..32]);
    U256::from(STATE_ROOT_STORAGE_POS.1).to_big_endian(&mut arr[32..64]);
    let slot = keccak(arr);
    insert_storage(storage_trie, slot.into_uint(), h2u(initial_trie_hash))
}

pub fn ger_contract_from_storage(storage_trie: &HashedPartialTrie) -> AccountRlp {
    AccountRlp {
        storage_root: storage_trie.hash(),
        ..GLOBAL_EXIT_ROOT_ACCOUNT
    }
}

pub fn scalable_contract_from_storage(storage_trie: &HashedPartialTrie) -> AccountRlp {
    AccountRlp {
        storage_root: storage_trie.hash(),
        ..Default::default()
    }
}
