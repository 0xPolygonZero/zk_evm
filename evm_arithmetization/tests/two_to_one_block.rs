use std::collections::HashMap;
use std::str::FromStr;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use evm_arithmetization::fixed_recursive_verifier::{
    extract_block_public_values, extract_two_to_one_block_hash,
};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockMetadata, PublicValues, TrieRoots};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

/// Get `GenerationInputs` for a simple token transfer txn, where the block has
/// the given timestamp.
fn empty_transfer(timestamp: u64) -> anyhow::Result<GenerationInputs> {
    init_logger();

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let sender = hex!("2c7536e3605d9c16a7a3d7b1898e529396a65c23");
    let to = hex!("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");

    let sender_state_key = keccak(sender);
    let to_state_key = keccak(to);

    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_state_key.as_bytes()).unwrap();

    let sender_account_before = AccountRlp {
        nonce: 5.into(),
        balance: eth_to_wei(100_000.into()),
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: keccak([]),
    };
    let to_account_before = AccountRlp::default();

    let state_trie_before: HashedPartialTrie = Node::Leaf {
        nibbles: sender_nibbles,
        value: rlp::encode(&sender_account_before).to_vec(),
    }
    .into();
    let checkpoint_state_trie_root = state_trie_before.hash();
    assert_eq!(
        checkpoint_state_trie_root,
        hex!("ef46022eafbc33d70e6ea9c6aef1074c1ff7ad36417ffbc64307ad3a8c274b75").into()
    );

    let tries_before = TrieInputs {
        state_trie: HashedPartialTrie::from(Node::Empty),
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        storage_tries: vec![],
    };

    // Generated using a little py-evm script.
    let txn = hex!("f861050a8255f094a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0648242421ba02c89eb757d9deeb1f5b3859a9d4d679951ef610ac47ad4608dc142beb1b7e313a05af7e9fbab825455d36c36c7f4cfcafbeafa9a77bdff936b52afb36d4fe4bcdd");
    let value = U256::from(100u32);

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

    let expected_state_trie_after: HashedPartialTrie = {
        let txdata_gas = 2 * 16;
        let gas_used = 21_000 + txdata_gas;

        let sender_account_after = AccountRlp {
            balance: sender_account_before.balance - value - gas_used * 10,
            nonce: sender_account_before.nonce + 1,
            ..sender_account_before
        };
        let to_account_after = AccountRlp {
            balance: value,
            ..to_account_before
        };

        let mut children = core::array::from_fn(|_| Node::Empty.into());
        children[sender_nibbles.get_nibble(0) as usize] = Node::Leaf {
            nibbles: sender_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&sender_account_after).to_vec(),
        }
        .into();
        children[to_nibbles.get_nibble(0) as usize] = Node::Leaf {
            nibbles: to_nibbles.truncate_n_nibbles_front(1),
            value: rlp::encode(&to_account_after).to_vec(),
        }
        .into();
        Node::Branch {
            children,
            value: vec![],
        }
        .into()
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: 21032.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(
        Nibbles::from_str("0x80").unwrap(),
        rlp::encode(&receipt_0).to_vec(),
    )?;
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    let _trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let trie_roots_after = TrieRoots {
        state_root: tries_before.state_trie.hash(),
        transactions_root: tries_before.transactions_trie.hash(),
        receipts_root: tries_before.receipts_trie.hash(),
    };
    let inputs = GenerationInputs {
        tries: tries_before.clone(),
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: tries_before.state_trie.hash(),
        block_metadata,
        ..Default::default()
    };

    Ok(inputs)
}

fn get_test_block_proof(
    timestamp: u64,
    all_circuits: &AllRecursiveCircuits<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    all_stark: &AllStark<GoldilocksField, 2>,
    config: &StarkConfig,
) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
    let inputs0 = empty_transfer(timestamp)?;
    let inputs = inputs0.clone();
    let dummy0 = GenerationInputs {
        txn_number_before: inputs.txn_number_before,
        gas_used_before: inputs.gas_used_after,
        gas_used_after: inputs.gas_used_after,
        signed_txn: None,
        global_exit_roots: vec![],
        withdrawals: vec![],
        tries: TrieInputs {
            state_trie: HashedPartialTrie::from(Node::Hash(inputs.trie_roots_after.state_root)),
            transactions_trie: HashedPartialTrie::from(Node::Hash(
                inputs.trie_roots_after.transactions_root,
            )),
            receipts_trie: HashedPartialTrie::from(Node::Hash(
                inputs.trie_roots_after.receipts_root,
            )),
            storage_tries: vec![],
        },
        trie_roots_after: inputs.trie_roots_after,
        checkpoint_state_trie_root: inputs.checkpoint_state_trie_root,
        contract_code: Default::default(),
        block_metadata: inputs.block_metadata.clone(),
        block_hashes: inputs.block_hashes.clone(),
        jumpdest_table: Default::default(),
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
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
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
