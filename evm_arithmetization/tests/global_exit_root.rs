#![cfg(feature = "cdk_erigon")]

use std::collections::HashMap;
use std::time::Duration;

use ethereum_types::H256;
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    ger_contract_from_storage, init_logger, preinitialized_state_and_storage_tries,
    scalable_account_nibbles, scalable_contract_from_storage, update_beacon_roots_account_storage,
    update_ger_account_storage, update_scalable_account_storage,
    ADDRESS_SCALABLE_L2_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_ACCOUNT, GLOBAL_EXIT_ROOT_ADDRESS_HASHED,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use keccak_hash::keccak;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;

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

    let (mut state_trie_before, mut storage_tries) = preinitialized_state_and_storage_tries()?;
    state_trie_before.insert(
        ger_account_nibbles(),
        rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
    )?;

    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    let mut ger_account_storage = HashedPartialTrie::from(Node::Empty);
    let mut scalable_account_storage = HashedPartialTrie::from(Node::Empty);

    storage_tries.push((GLOBAL_EXIT_ROOT_ADDRESS_HASHED, ger_account_storage.clone()));
    storage_tries.push((
        ADDRESS_SCALABLE_L2_ADDRESS_HASHED,
        scalable_account_storage.clone(),
    ));

    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    let ger_data = Some((H256::random(), H256::random()));

    let state_trie_after = {
        let mut trie = HashedPartialTrie::from(Node::Empty);
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        update_ger_account_storage(&mut ger_account_storage, ger_data)?;
        update_scalable_account_storage(
            &mut scalable_account_storage,
            &block_metadata,
            state_trie_before.hash(),
        )?;

        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);
        let ger_account = ger_contract_from_storage(&ger_account_storage);
        let scalable_account = scalable_contract_from_storage(&scalable_account_storage);

        trie.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;
        trie.insert(ger_account_nibbles(), rlp::encode(&ger_account).to_vec())?;
        trie.insert(
            scalable_account_nibbles(),
            rlp::encode(&scalable_account).to_vec(),
        )?;

        trie
    };

    let trie_roots_after = TrieRoots {
        state_root: state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txns: vec![],
        burn_addr: None,
        withdrawals: vec![],
        ger_data,
        tries: TrieInputs {
            state_trie: state_trie_before,
            transactions_trie,
            receipts_trie,
            storage_tries,
        },
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
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
