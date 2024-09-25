#![cfg(feature = "eth_mainnet")]

use evm_arithmetization::fixed_recursive_verifier::{
    extract_block_final_public_values, extract_two_to_one_block_hash,
};
use evm_arithmetization::proof::{FinalPublicValues, PublicValues};
use evm_arithmetization::testing_utils::{dummy_payload, init_logger};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, StarkConfig};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

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

    let inputs0_proof = all_circuits.prove_segment_aggregation(
        false,
        &dummy0_proof0[0],
        false,
        &dummy0_proof0[1],
    )?;
    let dummy0_proof =
        all_circuits.prove_segment_aggregation(false, &dummy1_proof[0], false, &dummy1_proof[1])?;

    let (agg_proof, pv) = all_circuits.prove_batch_aggregation(
        false,
        &inputs0_proof.proof_with_pis,
        inputs0_proof.public_values,
        false,
        &dummy0_proof.proof_with_pis,
        dummy0_proof.public_values,
    )?;

    all_circuits.verify_txn_aggregation(&agg_proof)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values = PublicValues::from_public_inputs(&agg_proof.public_inputs);
    assert_eq!(retrieved_public_values, pv);
    assert_eq!(
        pv.trie_roots_before.state_root,
        pv.extra_block_data.checkpoint_state_trie_root
    );

    let (block_proof, block_public_values) = all_circuits.prove_block(
        None, // We don't specify a previous proof, considering block 1 as the new checkpoint.
        &agg_proof, pv,
    )?;

    all_circuits.verify_block(&block_proof)?;

    let (wrapped_block_proof, block_final_public_values) =
        all_circuits.prove_block_wrapper(&block_proof, block_public_values)?;

    // Test retrieved final public values from the proof public inputs.
    let retrieved_final_public_values =
        FinalPublicValues::from_public_inputs(&wrapped_block_proof.public_inputs);
    assert_eq!(retrieved_final_public_values, block_final_public_values);

    all_circuits.verify_block_wrapper(&wrapped_block_proof)?;

    Ok(wrapped_block_proof)
}

#[ignore]
#[test]
fn test_two_to_one_block_aggregation() -> anyhow::Result<()> {
    init_logger();
    let some_timestamps = [127, 42, 65, 43];

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let all_circuits = AllRecursiveCircuits::new(
        &all_stark,
        &[
            16..17,
            8..9,
            12..13,
            9..10,
            8..9,
            6..7,
            17..18,
            17..18,
            7..8,
        ],
        &config,
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
