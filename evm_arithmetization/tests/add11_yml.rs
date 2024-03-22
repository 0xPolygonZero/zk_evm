use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::fixed_recursive_verifier::ProverOutputData;
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::prove;
use evm_arithmetization::verifier::verify_proof;
use evm_arithmetization::{AllRecursiveCircuits, AllStark, GenerationInputs, Node};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{KeccakGoldilocksConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

fn get_generation_inputs() -> GenerationInputs {
    let beneficiary = hex!("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba");
    let sender = hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    let to = hex!("095e7baea6a6c7c4c2dfeb977efac326af552d87");

    let beneficiary_state_key = keccak(beneficiary);
    let sender_state_key = keccak(sender);
    let to_hashed = keccak(to);

    let beneficiary_nibbles = Nibbles::from_bytes_be(beneficiary_state_key.as_bytes()).unwrap();
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_hashed.as_bytes()).unwrap();

    let code = [0x60, 0x01, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00];
    let code_hash = keccak(code);

    let beneficiary_account_before = AccountRlp {
        nonce: 1.into(),
        ..AccountRlp::default()
    };
    let sender_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        ..AccountRlp::default()
    };
    let to_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        code_hash,
        ..AccountRlp::default()
    };

    let mut state_trie_before = HashedPartialTrie::from(Node::Empty);
    state_trie_before.insert(
        beneficiary_nibbles,
        rlp::encode(&beneficiary_account_before).to_vec(),
    );
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec());
    state_trie_before.insert(to_nibbles, rlp::encode(&to_account_before).to_vec());

    let tries_before = TrieInputs {
        state_trie: state_trie_before.clone(),
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries: vec![(to_hashed, Node::Empty.into())],
    };

    let txn = hex!("f863800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffb600e63115a7362e7811894a91d8ba4330e526f22121c994c4692035dfdfd5a06198379fcac8de3dbfac48b165df4bf88e2088f294b61efb9a65fe2281c76e16");

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: 0xa868u64.into(),
        block_bloom: [0.into(); 8],
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let expected_state_trie_after = {
        let beneficiary_account_after = AccountRlp {
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let sender_account_after = AccountRlp {
            balance: 0xde0b6b3a75be550u64.into(),
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let to_account_after = AccountRlp {
            balance: 0xde0b6b3a76586a0u64.into(),
            code_hash,
            // Storage map: { 0 => 2 }
            storage_root: HashedPartialTrie::from(Node::Leaf {
                nibbles: Nibbles::from_h256_be(keccak([0u8; 32])),
                value: vec![2],
            })
            .hash(),
            ..AccountRlp::default()
        };

        let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
        expected_state_trie_after.insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_after).to_vec(),
        );
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec());
        expected_state_trie_after.insert(to_nibbles, rlp::encode(&to_account_after).to_vec());
        expected_state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: 0xa868u64.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(
        Nibbles::from_str("0x80").unwrap(),
        rlp::encode(&receipt_0).to_vec(),
    );
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    GenerationInputs {
        signed_txns: vec![txn.to_vec()],
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        block_metadata,
        checkpoint_state_trie_root: state_trie_before.hash(),
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0xa868u64.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    }
}
/// The `add11_yml` test case from https://github.com/ethereum/tests
#[test]
fn add11_yml() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let inputs = get_generation_inputs();

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let max_cpu_len_log = 20;
    let segment_idx = 0;
    let proof = prove::<F, C, D>(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        segment_idx,
        &mut timing,
        None,
    )?
    .expect("The initial registers should not be at the halt label.");
    timing.filter(Duration::from_millis(100)).print();

    verify_proof(&all_stark, proof, &config)
}

#[test]
#[ignore] // Too slow to run on CI.
fn add11_segments_aggreg() -> anyhow::Result<()> {
    init_logger();

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let inputs = get_generation_inputs();

    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[
            16..17,
            8..15,
            8..16,
            4..15,
            7..11,
            4..13,
            16..19,
            7..18,
            11..18,
        ], // Minimal ranges to prove an empty list
        &config,
    );

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let max_cpu_len_log = 14;

    let all_segment_proofs = all_circuits.prove_all_segments(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;

    // We need at least two segments for aggregation.
    assert!(all_segment_proofs.len() > 1);

    for segment_proof in &all_segment_proofs {
        let ProverOutputData {
            proof_with_pis: proof,
            ..
        } = segment_proof;
        all_circuits.verify_root(proof.clone())?;
    }

    let (mut aggreg_proof, mut aggreg_pv) = all_circuits.prove_segment_aggregation(
        false,
        &all_segment_proofs[0].proof_with_pis,
        all_segment_proofs[0].public_values.clone(),
        false,
        &all_segment_proofs[1].proof_with_pis,
        all_segment_proofs[1].public_values.clone(),
    )?;

    for seg in &all_segment_proofs[2..] {
        let ProverOutputData {
            proof_with_pis: proof,
            public_values,
        } = seg;
        (aggreg_proof, aggreg_pv) = all_circuits.prove_segment_aggregation(
            true,
            &aggreg_proof,
            aggreg_pv,
            false,
            proof,
            public_values.clone(),
        )?;
    }

    let _ = all_circuits.prove_block(None, &aggreg_proof, aggreg_pv)?;

    Ok(())
}

#[test]
fn test_two_reverts_with_exception() -> anyhow::Result<()> {
    // In this test, we have two reverted transactions:
    // - the first user code reaches a `fault_exception` because the gas consumption
    //   exceeds the transaction gas limit.
    // - the second user code throws a `stack_underflow` exception.
    let beneficiary = hex!("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba");
    let sender = hex!("af1276cbb260bb13deddb4209ae99ae6e497f446");
    let to_second = hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    let to_first = hex!("095e7baea6a6c7c4c2dfeb977efac326af552d87");

    let beneficiary_state_key = keccak(beneficiary);
    let sender_state_key = keccak(sender);
    let to_first_hashed = keccak(to_first);
    let to_second_hashed = keccak(to_second);

    let beneficiary_nibbles = Nibbles::from_bytes_be(beneficiary_state_key.as_bytes()).unwrap();
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_first_nibbles = Nibbles::from_bytes_be(to_first_hashed.as_bytes()).unwrap();
    let to_second_nibbles = Nibbles::from_bytes_be(to_second_hashed.as_bytes()).unwrap();

    let code = [0x60, 0x01, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00];
    let code2 = [0x50, 0x60, 0x01, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00];
    let code_hash = keccak(code);
    let second_code_hash = keccak(code2);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());
    contract_code.insert(second_code_hash, code2.to_vec());

    let sender_balance = 0x0de0b6b3a7640000u64.into();

    let beneficiary_account_before = AccountRlp {
        nonce: 2.into(),
        ..AccountRlp::default()
    };
    let sender_account_before = AccountRlp {
        // balance: 0x0de0b6b3a7640000u64.into(),
        balance: sender_balance,
        ..AccountRlp::default()
    };
    let to_first_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        code_hash,
        ..AccountRlp::default()
    };
    let to_second_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        code_hash: second_code_hash,
        ..AccountRlp::default()
    };

    let mut state_trie_before = HashedPartialTrie::from(Node::Empty);
    state_trie_before.insert(
        beneficiary_nibbles,
        rlp::encode(&beneficiary_account_before).to_vec(),
    );
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec());
    state_trie_before.insert(
        to_first_nibbles,
        rlp::encode(&to_first_account_before).to_vec(),
    );
    state_trie_before.insert(
        to_second_nibbles,
        rlp::encode(&to_second_account_before).to_vec(),
    );

    let tries_before = TrieInputs {
        state_trie: state_trie_before.clone(),
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries: vec![(to_first_hashed, Node::Empty.into())],
    };

    let txn = hex!("f862800a82753094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a08025a016b870246d69c0f1f3645e5989c93583553c40c35a0190070aeb6aea94d581c4a01fba541ebacbc2839e18c7f98b0b882fe31258e59fa4fffb80dddbee40013b25"); // txn that fails with low txn gas limit.
    let txn_2 = hex!("f867010a83061a8094a94f5374fce5edbc8e2a8697c15331677e6ebf0b87b1a2bc2ec500008025a03647e739ee5d1174a22dc14ec6ab06959d91729f8100ca1943d565ab115873d1a074038c793d5e7fc1b0fe14542229950f41dbdf18f77032a884565e190d545558");
    let txn1_gas_limit = 30_000;
    let txn2_gas_limit = 400_000;
    let gas_price = 10;

    // Since the transactions fail, they consume the two gas limits in the sender's
    // account, and do nothing else.
    let expected_state_trie_after = {
        let beneficiary_account_after = beneficiary_account_before;
        // This is the only account that changes: the nonce and the balance are updated.
        let sender_account_after = AccountRlp {
            balance: sender_balance - (txn1_gas_limit + txn2_gas_limit) * gas_price,
            nonce: 2.into(),
            ..AccountRlp::default()
        };
        let to_first_account_after = to_first_account_before;

        let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
        expected_state_trie_after.insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_after).to_vec(),
        );
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec());
        expected_state_trie_after.insert(
            to_first_nibbles,
            rlp::encode(&to_first_account_after).to_vec(),
        );
        expected_state_trie_after.insert(
            to_second_nibbles,
            rlp::encode(&to_second_account_before).to_vec(),
        );
        expected_state_trie_after
    };

    // Update expected receipts trie.
    let receipt_0 = LegacyReceiptRlp {
        status: false,
        cum_gas_used: txn1_gas_limit.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let receipt_1 = LegacyReceiptRlp {
        status: false,
        cum_gas_used: (txn1_gas_limit + txn2_gas_limit).into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(
        Nibbles::from_str("0x80").unwrap(),
        rlp::encode(&receipt_0).to_vec(),
    );
    receipts_trie.insert(
        Nibbles::from_str("0x01").unwrap(),
        rlp::encode(&receipt_1).to_vec(),
    );

    // Update expected transactions trie.
    let mut transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();
    transactions_trie.insert(Nibbles::from_str("0x01").unwrap(), txn_2.to_vec());

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: (txn1_gas_limit + txn2_gas_limit).into(),
        block_bloom: [0.into(); 8],
    };

    let inputs = GenerationInputs {
        signed_txns: vec![txn.to_vec(), txn_2.to_vec()],
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code: contract_code.clone(),
        block_metadata,
        checkpoint_state_trie_root: state_trie_before.hash(),
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: (txn1_gas_limit + txn2_gas_limit).into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[
            16..17,
            8..15,
            8..16,
            4..15,
            7..11,
            4..13,
            16..19,
            7..18,
            11..18,
        ], // Minimal ranges to prove an empty list
        &config,
    );

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let max_cpu_len_log = 14;

    let all_segment_proofs = &all_circuits.prove_all_segments(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;

    for segment_proof in all_segment_proofs {
        let ProverOutputData {
            proof_with_pis: proof,
            ..
        } = segment_proof;
        all_circuits.verify_root(proof.clone())?;
    }

    let (mut aggreg_proof, mut aggreg_pv) = all_circuits.prove_segment_aggregation(
        false,
        &all_segment_proofs[0].proof_with_pis,
        all_segment_proofs[0].public_values.clone(),
        false,
        &all_segment_proofs[1].proof_with_pis,
        all_segment_proofs[1].public_values.clone(),
    )?;

    for seg in &all_segment_proofs[2..] {
        let ProverOutputData {
            proof_with_pis: proof,
            public_values,
        } = seg;
        (aggreg_proof, aggreg_pv) = all_circuits.prove_segment_aggregation(
            true,
            &aggreg_proof,
            aggreg_pv,
            false,
            proof,
            public_values.clone(),
        )?;
    }

    let (block_proof, _) = all_circuits.prove_block(None, &aggreg_proof, aggreg_pv)?;
    all_circuits.verify_block(&block_proof)
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
