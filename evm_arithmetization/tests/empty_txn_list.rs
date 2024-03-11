use core::marker::PhantomData;
use std::collections::HashMap;
use std::time::Duration;

use ethereum_types::{BigEndianHash, H256};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, PublicValues, TrieRoots};
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    init_logger, preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
    BEACON_ROOTS_CONTRACT_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_ACCOUNT,
};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use log::info;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Execute the empty list of transactions, i.e. a no-op.
#[test]
#[ignore] // Too slow to run on CI.
fn test_empty_txn_list() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let block_metadata = BlockMetadata {
        block_number: 1.into(),
        block_timestamp: 1.into(),
        parent_beacon_block_root: H256(hex!(
            "44e2566c06c03b132e0ede3e90af477ebca74393b89dd6cb29f9c79cbcb6e963"
        )),
        ..Default::default()
    };

    let (state_trie, storage_tries) = preinitialized_state_and_storage_tries();
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let state_trie_after: HashedPartialTrie = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        );
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        state_trie_after.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        );
        state_trie_after.insert(
            ger_account_nibbles(),
            rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
        );

        state_trie_after
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    // No transactions, but the beacon roots contract has been updated.
    let trie_roots_after = TrieRoots {
        state_root: state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };
    let mut initial_block_hashes = vec![H256::default(); 256];
    initial_block_hashes[255] = H256::from_uint(&0x200.into());
    let inputs1 = GenerationInputs {
        signed_txn: None,
        withdrawals: vec![],
        global_exit_roots: vec![],
        tries: TrieInputs {
            state_trie: state_trie.clone(),
            transactions_trie: transactions_trie.clone(),
            receipts_trie: receipts_trie.clone(),
            storage_tries: storage_tries.clone(),
        },
        trie_roots_after,
        contract_code: contract_code.clone(),
        checkpoint_state_trie_root: state_trie.hash(),
        block_metadata: block_metadata.clone(),
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_hashes: BlockHashes {
            prev_hashes: initial_block_hashes.clone(),
            cur_hash: H256::default(),
        },
    };

    // Initialize the preprocessed circuits for the zkEVM.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        // Minimal ranges to prove an empty list
        &[16..17, 11..13, 13..15, 14..15, 9..10, 12..13, 17..18],
        &config,
    );

    {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D> {
            _phantom: PhantomData::<C>,
        };

        let timing = TimingTree::new("serialize AllRecursiveCircuits", log::Level::Info);
        let all_circuits_bytes = all_circuits
            .to_bytes(false, &gate_serializer, &generator_serializer)
            .map_err(|_| anyhow::Error::msg("AllRecursiveCircuits serialization failed."))?;
        timing.filter(Duration::from_millis(100)).print();
        info!(
            "AllRecursiveCircuits length: {} bytes",
            all_circuits_bytes.len()
        );

        let timing = TimingTree::new("deserialize AllRecursiveCircuits", log::Level::Info);
        let all_circuits_from_bytes = AllRecursiveCircuits::<F, C, D>::from_bytes(
            &all_circuits_bytes,
            false,
            &gate_serializer,
            &generator_serializer,
        )
        .map_err(|_| anyhow::Error::msg("AllRecursiveCircuits deserialization failed."))?;
        timing.filter(Duration::from_millis(100)).print();

        assert_eq!(all_circuits, all_circuits_from_bytes);
    }

    let mut timing = TimingTree::new("prove first dummy", log::Level::Info);
    let (root_proof, public_values) =
        all_circuits.prove_root(&all_stark, &config, inputs1, &mut timing, None)?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof.clone())?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(&root_proof.public_inputs);
    assert_eq!(retrieved_public_values, public_values);

    // We cannot duplicate the proof here because even though there weren't any
    // transactions, the state has mutated when updating the beacon roots contract.
    let trie_roots_after = TrieRoots {
        state_root: state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };
    let inputs2 = GenerationInputs {
        signed_txn: None,
        withdrawals: vec![],
        global_exit_roots: vec![],
        tries: TrieInputs {
            state_trie: state_trie_after,
            transactions_trie,
            receipts_trie,
            storage_tries: vec![(
                H256(BEACON_ROOTS_CONTRACT_ADDRESS_HASHED),
                beacon_roots_account_storage,
            )],
        },
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: state_trie.hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_hashes: BlockHashes {
            prev_hashes: initial_block_hashes,
            cur_hash: H256::default(),
        },
    };

    let mut timing = TimingTree::new("prove second dummy", log::Level::Info);
    let (root_proof2, public_values2) =
        all_circuits.prove_root(&all_stark, &config, inputs2, &mut timing, None)?;
    timing.filter(Duration::from_millis(100)).print();
    all_circuits.verify_root(root_proof2.clone())?;

    let (agg_proof, agg_public_values) = all_circuits.prove_aggregation(
        false,
        &root_proof,
        public_values.clone(),
        false,
        &root_proof2,
        public_values2,
    )?;
    all_circuits.verify_aggregation(&agg_proof)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(&agg_proof.public_inputs);
    assert_eq!(retrieved_public_values, agg_public_values);

    let (block_proof, block_public_values) =
        all_circuits.prove_block(None, &agg_proof, agg_public_values)?;
    all_circuits.verify_block(&block_proof)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(&block_proof.public_inputs);
    assert_eq!(retrieved_public_values, block_public_values);

    // Get the verifier associated to these preprocessed circuits, and have it
    // verify the block_proof.
    let verifier = all_circuits.final_verifier_data();
    verifier.verify(block_proof)
}
