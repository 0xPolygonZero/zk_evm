//! A set of utility functions and constants to be used by `evm_arithmetization`
//! unit and integration tests.

use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::plonk::circuit_data::CircuitConfig;
use starky::config::StarkConfig;

pub use crate::cpu::kernel::cancun_constants::*;
pub use crate::cpu::kernel::constants::global_exit_root::*;
use crate::generation::{TrieInputs, TrimmedGenerationInputs};
use crate::proof::TrieRoots;
#[cfg(test)]
use crate::witness::operation::Operation;
use crate::{
    generation::mpt::AccountRlp, proof::BlockMetadata, util::h2u, GenerationInputs,
    GenerationSegmentData, SegmentDataIterator,
};

pub const EMPTY_NODE_HASH: H256 = H256(hex!(
    "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
));

/// The recursion threshold when using test configurations
pub const TEST_THRESHOLD_DEGREE_BITS: usize = 10;

/// The recursion threshold for 2-to-1 block circuit.
pub const TWO_TO_ONE_BLOCK_CIRCUIT_TEST_THRESHOLD_DEGREE_BITS: usize = 13;

/// A fast STARK config for testing purposes only.
pub const TEST_STARK_CONFIG: StarkConfig = StarkConfig {
    security_bits: 1,
    num_challenges: 1,
    fri_config: FriConfig {
        rate_bits: 1,
        cap_height: 4,
        proof_of_work_bits: 1,
        reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
        num_query_rounds: 1,
    },
};

/// A fast Circuit config for testing purposes only.
pub const TEST_RECURSION_CONFIG: CircuitConfig = CircuitConfig {
    num_wires: 135,
    num_routed_wires: 80,
    num_constants: 2,
    use_base_arithmetic_gate: true,
    security_bits: 1,
    num_challenges: 1,
    zero_knowledge: false,
    max_quotient_degree_factor: 8,
    fri_config: FriConfig {
        rate_bits: 3,
        cap_height: 4,
        proof_of_work_bits: 1,
        reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
        num_query_rounds: 1,
    },
};

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

fn empty_payload() -> Result<GenerationInputs> {
    // Set up default block metadata
    let block_metadata = BlockMetadata {
        block_beneficiary: Address::zero(),
        block_timestamp: U256::zero(),
        block_number: U256::one(),
        block_difficulty: U256::zero(),
        block_random: H256::zero(),
        block_gaslimit: U256::zero(),
        block_chain_id: U256::one(),
        block_base_fee: U256::zero(),
        ..Default::default()
    };

    // Initialize an empty state trie and storage tries
    let state_trie_before = HashedPartialTrie::from(crate::Node::Empty);
    let storage_tries = Vec::new();
    let checkpoint_state_trie_root = state_trie_before.hash();

    // Prepare the tries without any transactions or receipts
    let tries_before = TrieInputs {
        state_trie: state_trie_before.clone(),
        storage_tries: storage_tries.clone(),
        transactions_trie: HashedPartialTrie::from(crate::Node::Empty),
        receipts_trie: HashedPartialTrie::from(crate::Node::Empty),
    };

    // The expected state trie after execution remains the same as before
    let expected_state_trie_after = state_trie_before;

    // Compute the trie roots after execution
    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: tries_before.transactions_trie.hash(),
        receipts_root: tries_before.receipts_trie.hash(),
    };

    // Construct the GenerationInputs without any transactions or state changes
    let inputs = GenerationInputs {
        tries: tries_before,
        trie_roots_after,
        checkpoint_state_trie_root,
        block_metadata,
        ..Default::default()
    };

    Ok(inputs)
}

pub fn segment_with_empty_tables() -> Result<(
    TrimmedGenerationInputs<GoldilocksField>,
    GenerationSegmentData,
)> {
    let payload = empty_payload()?;
    let max_cpu_len_log = Some(7);
    let mut segment_iterator =
        SegmentDataIterator::<GoldilocksField>::new(&payload, max_cpu_len_log);
    let (trimmed_inputs, segment_data) = segment_iterator.next().unwrap()?;

    Ok((trimmed_inputs, segment_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic;

    // Ensures that there are no Keccak and Logic ops in the segment.
    #[test]
    fn test_segment_with_empty_tables() -> Result<()> {
        let (_, segment_data) = segment_with_empty_tables()?;

        let opcode_counts = &segment_data.opcode_counts;
        assert!(!opcode_counts.0.contains_key((&Operation::KeccakGeneral)));
        assert!(!opcode_counts.0.contains_key(&Operation::BinaryLogic(logic::Op::And)));
        assert!(!opcode_counts.0.contains_key(&Operation::BinaryLogic(logic::Op::Or)));
        assert!(!opcode_counts.0.contains_key(&Operation::BinaryLogic(logic::Op::Xor)));

        Ok(())
    }
}
