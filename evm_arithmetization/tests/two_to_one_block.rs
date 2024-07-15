use std::collections::HashMap;

use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::fixed_recursive_verifier::{
    extract_block_public_values, extract_two_to_one_block_hash,
};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockMetadata, PublicValues, TrieRoots};
use evm_arithmetization::testing_utils::{
    init_logger, preinitialized_state, preinitialized_state_with_updated_storage,
};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use smt_trie::db::MemoryDb;
use smt_trie::smt::Smt;
use smt_trie::utils::hashout2u;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Get `GenerationInputs` for an empty block with the given timestamp.
fn empty_transfer(timestamp: u64) -> anyhow::Result<(GenerationInputs, Smt<MemoryDb>)> {
    init_logger();

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    let state_smt_before = preinitialized_state();
    let checkpoint_state_trie_root = H256::from_uint(&hashout2u(state_smt_before.root));

    let tries_before = TrieInputs {
        state_smt: state_smt_before.serialize(),
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
    };

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

    let contract_code = HashMap::new();

    let expected_smt_after = preinitialized_state_with_updated_storage(&block_metadata, &[]);

    let trie_roots_after = TrieRoots {
        state_root: H256::from_uint(&hashout2u(expected_smt_after.root)),
        transactions_root: HashedPartialTrie::from(Node::Empty).hash(),
        receipts_root: HashedPartialTrie::from(Node::Empty).hash(),
    };

    let inputs = GenerationInputs {
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root,
        block_metadata,
        ..Default::default()
    };

    Ok((inputs, expected_smt_after))
}

fn get_test_block_proof(
    timestamp: u64,
    all_circuits: &AllRecursiveCircuits<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    all_stark: &AllStark<GoldilocksField, 2>,
    config: &StarkConfig,
) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
    let (inputs0, state_smt) = empty_transfer(timestamp)?;
    let inputs = inputs0.clone();
    let dummy0 = GenerationInputs {
        txn_number_before: inputs.txn_number_before,
        gas_used_before: inputs.gas_used_after,
        gas_used_after: inputs.gas_used_after,
        signed_txn: None,
        global_exit_roots: vec![],
        withdrawals: vec![],
        tries: TrieInputs {
            state_smt: state_smt.serialize(),
            transactions_trie: HashedPartialTrie::from(Node::Hash(
                inputs.trie_roots_after.transactions_root,
            )),
            receipts_trie: HashedPartialTrie::from(Node::Hash(
                inputs.trie_roots_after.receipts_root,
            )),
        },
        trie_roots_after: inputs.trie_roots_after,
        checkpoint_state_trie_root: inputs.checkpoint_state_trie_root,
        contract_code: Default::default(),
        block_metadata: inputs.block_metadata.clone(),
        block_hashes: inputs.block_hashes.clone(),
    };

    let timing = &mut TimingTree::new(&format!("Blockproof {timestamp}"), log::Level::Info);
    let (root_proof0, pv0) = all_circuits.prove_root(all_stark, config, inputs0, timing, None)?;
    all_circuits.verify_root(root_proof0.clone())?;
    let (dummy_proof0, dummy_pv0) =
        all_circuits.prove_root(all_stark, config, dummy0, timing, None)?;
    all_circuits.verify_root(dummy_proof0.clone())?;

    let (agg_proof0, pv0) = all_circuits.prove_aggregation(
        false,
        &root_proof0,
        pv0,
        false,
        &dummy_proof0,
        dummy_pv0,
    )?;

    all_circuits.verify_aggregation(&agg_proof0)?;

    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values0 = PublicValues::from_public_inputs(&agg_proof0.public_inputs);
    assert_eq!(retrieved_public_values0, pv0);
    assert_eq!(
        pv0.trie_roots_before.state_root,
        pv0.extra_block_data.checkpoint_state_trie_root
    );

    let (block_proof0, block_public_values) = all_circuits.prove_block(
        None, // We don't specify a previous proof, considering block 1 as the new checkpoint.
        &agg_proof0,
        pv0.clone(),
    )?;

    let pv_block = PublicValues::from_public_inputs(&block_proof0.public_inputs);
    assert_eq!(block_public_values, pv_block);

    Ok(block_proof0)
}

#[ignore]
#[test]
fn test_two_to_one_block_aggregation() -> anyhow::Result<()> {
    init_logger();
    let some_timestamps = [127, 42, 65, 43];

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 8..9, 13..14, 14..15, 10..11, 12..13, 17..18, 6..7],
        &config,
    );

    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| get_test_block_proof(ts, &all_circuits, &all_stark, &config))
        .collect::<anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>>>()?;

    unrelated_block_proofs
        .iter()
        .try_for_each(|bp| all_circuits.verify_block(bp))?;

    let bp = unrelated_block_proofs;

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
                    let public_values = extract_block_public_values(&block_proof.public_inputs);
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
