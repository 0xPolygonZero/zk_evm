use core::marker::PhantomData;
use std::collections::HashMap;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{BigEndianHash, H256};
use evm_arithmetization::fixed_recursive_verifier::ProverOutputData;
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{
    BlockHashes, BlockMetadata, FinalPublicValues, PublicValues, TrieRoots,
};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
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
        ..Default::default()
    };

    let state_trie = HashedPartialTrie::from(Node::Empty);
    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);
    let storage_tries = vec![];

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    // No transactions, so no trie roots change.
    let trie_roots_after = TrieRoots {
        state_root: state_trie.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let mut initial_block_hashes = vec![H256::default(); 256];
    initial_block_hashes[255] = H256::from_uint(&0x200.into());
    let inputs = GenerationInputs {
        signed_txns: vec![],
        withdrawals: vec![],
        tries: TrieInputs {
            state_trie,
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
            prev_hashes: initial_block_hashes,
            cur_hash: H256::default(),
        },
    };

    // Initialize the preprocessed circuits for the zkEVM.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        // Minimal ranges to prove an empty list
        &[16..17, 8..9, 8..10, 5..8, 8..9, 4..6, 16..17, 16..17, 7..17],
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

    let max_cpu_len_log = 9;
    let mut timing = TimingTree::new("prove", log::Level::Info);

    let segment_proofs_data = &all_circuits.prove_all_segments(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;

    assert_eq!(segment_proofs_data.len(), 3);
    for proof_data in segment_proofs_data {
        let ProverOutputData {
            proof_with_pis: proof,
            ..
        } = proof_data;
        all_circuits.verify_root(proof.clone())?;
    }

    let first_mem_before = segment_proofs_data[0]
        .public_values
        .mem_before
        .mem_cap
        .clone();
    let second_mem_before = segment_proofs_data[1]
        .public_values
        .mem_before
        .mem_cap
        .clone();
    let third_mem_before = segment_proofs_data[2]
        .public_values
        .mem_before
        .mem_cap
        .clone();

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(
        &segment_proofs_data[0].proof_with_pis.public_inputs,
        first_mem_before.len(),
    );
    assert_eq!(
        retrieved_public_values,
        segment_proofs_data[0].public_values
    );

    let retrieved_public_values = PublicValues::from_public_inputs(
        &segment_proofs_data[1].proof_with_pis.public_inputs,
        second_mem_before.len(),
    );
    assert_eq!(
        retrieved_public_values,
        segment_proofs_data[1].public_values
    );

    let retrieved_public_values = PublicValues::from_public_inputs(
        &segment_proofs_data[2].proof_with_pis.public_inputs,
        third_mem_before.len(),
    );
    assert_eq!(
        retrieved_public_values,
        segment_proofs_data[2].public_values
    );

    // We can duplicate the proofs here because the state hasn't mutated.
    let aggregation_output_data = all_circuits.prove_segment_aggregation(
        false,
        &segment_proofs_data[0],
        false,
        &segment_proofs_data[1],
    )?;
    all_circuits.verify_segment_aggregation(&aggregation_output_data.proof_with_pis)?;

    let aggregation_output_data = all_circuits.prove_segment_aggregation(
        true,
        &aggregation_output_data,
        false,
        &segment_proofs_data[2],
    )?;
    all_circuits.verify_segment_aggregation(&aggregation_output_data.proof_with_pis)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(
        &aggregation_output_data.proof_with_pis.public_inputs,
        aggregation_output_data
            .public_values
            .mem_before
            .mem_cap
            .len(),
    );
    assert_eq!(
        retrieved_public_values,
        aggregation_output_data.public_values
    );

    let (txn_proof, txn_public_values) = all_circuits.prove_transaction_aggregation(
        false,
        &aggregation_output_data.proof_with_pis,
        aggregation_output_data.public_values.clone(),
        false,
        &aggregation_output_data.proof_with_pis,
        aggregation_output_data.public_values,
    )?;
    all_circuits.verify_txn_aggregation(&txn_proof)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(
        &txn_proof.public_inputs,
        txn_public_values.mem_before.mem_cap.len(),
    );
    assert_eq!(retrieved_public_values, txn_public_values);

    let (block_proof, block_public_values) =
        all_circuits.prove_block(None, &txn_proof, txn_public_values)?;
    all_circuits.verify_block(&block_proof)?;

    // Test retrieved final public values from the proof public inputs.
    let retrieved_public_values = FinalPublicValues::from_public_inputs(&block_proof.public_inputs);
    assert_eq!(retrieved_public_values, block_public_values);

    // Get the verifier associated to these preprocessed circuits, and have it
    // verify the block_proof.
    let verifier = all_circuits.final_verifier_data();
    verifier.verify(block_proof)
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
