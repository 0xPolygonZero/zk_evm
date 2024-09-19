#![cfg(feature = "cdk_erigon")]

use std::collections::HashMap;
use std::time::Duration;

use ethereum_types::{BigEndianHash, H256};
use evm_arithmetization::generation::{GenerationInputs, InputStateTrie, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    ger_account_nibbles, init_logger, preinitialized_state_smt_ger,
    preinitialized_state_with_updated_storage, scalable_account_nibbles, set_account,
    update_ger_account_storage, update_scalable_account_storage,
    ADDRESS_SCALABLE_L2_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_ADDRESS_HASHED,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use keccak_hash::keccak;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use smt_trie::db::MemoryDb;
use smt_trie::smt::Smt;
use smt_trie::utils::hashout2u;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Test pre-state execution as performed by cdk-erigon.
#[test]
fn test_global_exit_root() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let block_metadata = BlockMetadata {
        block_timestamp: 1.into(),
        block_number: 42.into(),
        ..BlockMetadata::default()
    };

    let mut state_smt_before = preinitialized_state_smt_ger();
    // let mut state_trie_before = HashedPartialTrie::from(Node::Empty);
    // let mut storage_tries = vec![];
    // state_trie_before.insert(
    //     ger_account_nibbles(),
    //     rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
    // )?;

    // let mut ger_account_storage = HashedPartialTrie::from(Node::Empty);
    // let mut scalable_account_storage = HashedPartialTrie::from(Node::Empty);

    // storage_tries.push((GLOBAL_EXIT_ROOT_ADDRESS_HASHED,
    // ger_account_storage.clone())); storage_tries.push((
    //     ADDRESS_SCALABLE_L2_ADDRESS_HASHED,
    //     scalable_account_storage.clone(),
    // ));

    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    let ger_data = Some((H256::random(), H256::random()));

    let expected_smt_after: Smt<MemoryDb> = {
        let mut smt = preinitialized_state_with_updated_storage(&[]);
        // TODO: Update GER and scalable account.

        smt
    };

    let trie_roots_after = TrieRoots {
        state_root: H256::from_uint(&hashout2u(expected_smt_after.root)),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs::<F> {
        signed_txns: vec![],
        burn_addr: None,
        withdrawals: vec![],
        ger_data,
        tries: TrieInputs {
            state_trie: InputStateTrie::Type2(state_smt_before.serialize()),
            transactions_trie,
            receipts_trie,
            storage_tries: None,
        },
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        checkpoint_consolidated_hash: [F::ZERO; NUM_HASH_OUT_ELTS],
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    let max_cpu_len_log = 20;

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let proofs = prove_all_segments::<F, C, D>(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;
    timing.filter(Duration::from_millis(100)).print();

    verify_all_proofs(&all_stark, &proofs, &config)
}
