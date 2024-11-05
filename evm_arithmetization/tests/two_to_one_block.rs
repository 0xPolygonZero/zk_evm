#![cfg(feature = "eth_mainnet")]

use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::fixed_recursive_verifier::{
    extract_block_final_public_values, extract_two_to_one_block_hash, RecursionConfig,
};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{
    BlockMetadata, FinalPublicValues, PublicValues, TrieRoots, EMPTY_CONSOLIDATED_BLOCKHASH,
};
use evm_arithmetization::testing_utils::*;
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Get `GenerationInputs` for a dummy payload, where the block has the given
/// timestamp.
fn dummy_payload(timestamp: u64, is_first_payload: bool) -> anyhow::Result<GenerationInputs<F>> {
    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: timestamp.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        ..Default::default()
    };

    let (mut state_trie_before, mut storage_tries) = preinitialized_state_and_storage_tries()?;
    let checkpoint_state_trie_root = state_trie_before.hash();
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();

    update_beacon_roots_account_storage(
        &mut beacon_roots_account_storage,
        block_metadata.block_timestamp,
        block_metadata.parent_beacon_block_root,
    )?;
    let updated_beacon_roots_account =
        beacon_roots_contract_from_storage(&beacon_roots_account_storage);

    if !is_first_payload {
        // This isn't the first dummy payload being processed. We need to update the
        // initial state trie to account for the update on the beacon roots contract.
        state_trie_before.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&updated_beacon_roots_account).to_vec(),
        )?;
        storage_tries[0].1 = beacon_roots_account_storage;
    }

    let state_trie_before = get_state_world(state_trie_before, storage_tries);

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        // storage_tries,
        ..Default::default()
    };

    let expected_state_trie_after: HashedPartialTrie = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);
        state_trie_after.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&updated_beacon_roots_account).to_vec(),
        )?;

        state_trie_after
    };

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: tries_before.transactions_trie.hash(),
        receipts_root: tries_before.receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        tries: tries_before.clone(),
        burn_addr: None,
        trie_roots_after,
        checkpoint_state_trie_root,
        checkpoint_consolidated_hash: EMPTY_CONSOLIDATED_BLOCKHASH.map(F::from_canonical_u64),
        block_metadata,
        ..Default::default()
    };

    Ok(inputs)
}

fn get_test_block_proof(
    timestamp: u64,
    all_circuits: &AllRecursiveCircuits,
    all_stark: &AllStark<GoldilocksField, 2>,
    config: &StarkConfig,
) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
    let dummy0 = dummy_payload(timestamp, true)?;
    let dummy1 = dummy_payload(timestamp, false)?;

    let timing = &mut TimingTree::new(&format!("Blockproof {timestamp}"), log::Level::Info);
    let dummy0_proof0 =
        all_circuits.prove_all_segments(all_stark, config, dummy0, 20, timing, None)?;
    let dummy1_proof =
        all_circuits.prove_all_segments(all_stark, config, dummy1, 20, timing, None)?;

    let inputs0_proof =
        all_circuits.prove_segment_aggregation(&dummy0_proof0[0], &dummy0_proof0[1])?;
    let dummy0_proof =
        all_circuits.prove_segment_aggregation(&dummy1_proof[0], &dummy1_proof[1])?;

    let batch_proof = all_circuits.prove_batch_aggregation(
        false,
        &inputs0_proof.proof_with_pvs,
        false,
        &dummy0_proof.proof_with_pvs,
    )?;

    all_circuits.verify_batch_aggregation(&batch_proof.intern)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values =
        PublicValues::from_public_inputs(&batch_proof.intern.public_inputs);
    assert_eq!(retrieved_public_values, batch_proof.public_values);
    assert_eq!(
        batch_proof.public_values.trie_roots_before.state_root,
        batch_proof
            .public_values
            .extra_block_data
            .checkpoint_state_trie_root
    );

    let block_proof = all_circuits.prove_block(
        None, // We don't specify a previous proof, considering block 1 as the new checkpoint.
        &batch_proof,
    )?;

    all_circuits.verify_block(&block_proof.intern)?;

    let (wrapped_block_proof, block_final_public_values) =
        all_circuits.prove_block_wrapper(&block_proof)?;

    // Test retrieved final public values from the proof public inputs.
    let retrieved_final_public_values =
        FinalPublicValues::from_public_inputs(&wrapped_block_proof.public_inputs);
    assert_eq!(retrieved_final_public_values, block_final_public_values);

    all_circuits.verify_block_wrapper(&wrapped_block_proof)?;

    Ok(wrapped_block_proof)
}

#[test]
fn test_two_to_one_block_aggregation() -> anyhow::Result<()> {
    init_logger();
    let some_timestamps = [127, 42, 65, 43];

    let all_stark = AllStark::<F, D>::default();
    let config = TEST_STARK_CONFIG;

    let all_circuits = AllRecursiveCircuits::new(
        &all_stark,
        &[16..17, 8..9, 12..13, 8..9, 8..9, 6..7, 17..18, 16..17, 7..8],
        RecursionConfig::test_config(),
    );

    let bp = some_timestamps
        .iter()
        .map(|&ts| get_test_block_proof(ts, &all_circuits, &all_stark, &config))
        .collect::<anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>>>()?;

    {
        // Aggregate the same proof twice
        let aggproof_42_42 = all_circuits.prove_two_to_one_block(&bp[0], false, &bp[0], false)?;
        all_circuits.verify_two_to_one_block(&aggproof_42_42)?;
    }

    {
        // Binary tree reduction
        //
        //  A    B    C    D    Blockproofs (base case)
        //   \  /      \  /
        //  (A, B)    (C, D)    Two-to-one block aggregation proofs
        //     \       /
        //   ((A,B), (C,D))     Two-to-one block aggregation proofs

        let aggproof01 = all_circuits.prove_two_to_one_block(&bp[0], false, &bp[1], false)?;
        all_circuits.verify_two_to_one_block(&aggproof01)?;

        let aggproof23 = all_circuits.prove_two_to_one_block(&bp[2], false, &bp[3], false)?;
        all_circuits.verify_two_to_one_block(&aggproof23)?;

        let aggproof0123 =
            all_circuits.prove_two_to_one_block(&aggproof01, true, &aggproof23, true)?;
        all_circuits.verify_two_to_one_block(&aggproof0123)?;

        {
            // Compute Merkle root from public inputs of block proofs.
            // Leaves
            let mut hashes: Vec<_> = bp
                .iter()
                .map(|block_proof| {
                    let public_values =
                        extract_block_final_public_values(&block_proof.public_inputs);
                    PoseidonHash::hash_no_pad(public_values)
                })
                .collect();

            // Inner nodes
            hashes.extend_from_within(0..hashes.len());
            let half = hashes.len() / 2;
            for i in 0..half - 1 {
                hashes[half + i] = PoseidonHash::two_to_one(hashes[2 * i], hashes[2 * i + 1]);
            }
            let merkle_root = hashes[hashes.len() - 2].elements;

            assert_eq!(
                extract_two_to_one_block_hash(&aggproof0123.public_inputs),
                &merkle_root,
                "Merkle root of verifier's verification tree did not match merkle root in public inputs."
            );
        }
    }

    {
        // Foldleft
        //
        //  A    B    C    D    Blockproofs (base case)
        //   \  /    /    /
        //  (A, B)  /    /      Two-to-one block aggregation proofs
        //     \   /    /
        //  ((A,B), C) /        Two-to-one block aggregation proofs
        //       \    /
        //  (((A,B),C),D)       Two-to-one block aggregation proofs

        let aggproof01 = all_circuits.prove_two_to_one_block(&bp[0], false, &bp[1], false)?;
        all_circuits.verify_two_to_one_block(&aggproof01)?;

        let aggproof012 = all_circuits.prove_two_to_one_block(&aggproof01, true, &bp[2], false)?;
        all_circuits.verify_two_to_one_block(&aggproof012)?;

        let aggproof0123 =
            all_circuits.prove_two_to_one_block(&aggproof012, true, &bp[3], false)?;
        all_circuits.verify_two_to_one_block(&aggproof0123)?;
    }

    {
        // Foldright
        //
        //  A    B    C    D    Blockproofs (base case)
        //   \    \   \   /
        //    \    \   (C,D)    Two-to-one block aggregation proofs
        //     \     \  /
        //      \ (B,(C, D))    Two-to-one block aggregation proofs
        //       \   /
        //     (A,(B,(C,D)))    Two-to-one block aggregation proofs

        let aggproof23 = all_circuits.prove_two_to_one_block(&bp[2], false, &bp[3], false)?;
        all_circuits.verify_two_to_one_block(&aggproof23)?;

        let aggproof123 = all_circuits.prove_two_to_one_block(&bp[1], false, &aggproof23, true)?;
        all_circuits.verify_two_to_one_block(&aggproof123)?;

        let aggproof0123 =
            all_circuits.prove_two_to_one_block(&bp[0], false, &aggproof123, true)?;
        all_circuits.verify_two_to_one_block(&aggproof0123)?;
    }

    Ok(())
}
