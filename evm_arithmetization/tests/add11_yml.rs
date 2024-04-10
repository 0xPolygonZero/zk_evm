use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::fixed_recursive_verifier::ProverOutputData;
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::{generate_all_data_segments, prove};
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
        state_trie: state_trie_before,
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
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        block_metadata,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
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

    let max_cpu_len_log = 20;
    let mut data = generate_all_data_segments::<F>(Some(max_cpu_len_log), inputs.clone())?;

    let mut timing = TimingTree::new("prove", log::Level::Debug);

    let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut data[0], &mut timing, None)?;
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

    let all_segment_proofs = &all_circuits.prove_all_segments(
        &all_stark,
        &config,
        inputs.clone(),
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

    assert_eq!(all_segment_proofs.len(), 3);

    let (first_aggreg_proof, first_aggreg_pv) = all_circuits.prove_segment_aggregation(
        false,
        &all_segment_proofs[0].proof_with_pis,
        all_segment_proofs[0].public_values.clone(),
        false,
        &all_segment_proofs[1].proof_with_pis,
        all_segment_proofs[1].public_values.clone(),
    )?;
    all_circuits.verify_segment_aggregation(&first_aggreg_proof)?;

    let (second_aggreg_proof, second_aggreg_pv) = all_circuits.prove_segment_aggregation(
        true,
        &first_aggreg_proof,
        first_aggreg_pv,
        false,
        &all_segment_proofs[2].proof_with_pis,
        all_segment_proofs[2].public_values.clone(),
    )?;
    all_circuits.verify_segment_aggregation(&second_aggreg_proof)?;

    // We need two transactions to carry out a transaction aggregation. So we create
    // a dummy segment aggregation.
    let trie_roots_before = TrieRoots {
        state_root: inputs.tries.state_trie.hash(),
        transactions_root: inputs.tries.transactions_trie.hash(),
        receipts_root: inputs.tries.receipts_trie.hash(),
    };

    let dummy_inputs = GenerationInputs {
        txn_number_before: 0.into(),
        gas_used_before: inputs.gas_used_before,
        gas_used_after: inputs.gas_used_before,
        signed_txn: None,
        withdrawals: vec![],
        tries: inputs.tries,
        trie_roots_after: trie_roots_before,
        checkpoint_state_trie_root: inputs.checkpoint_state_trie_root,
        contract_code: inputs.contract_code,
        block_metadata: inputs.block_metadata,
        block_hashes: inputs.block_hashes,
    };

    let max_cpu_len_log = 13;

    let dummy_segs = all_circuits.prove_all_segments(
        &all_stark,
        &config,
        dummy_inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;

    assert_eq!(dummy_segs.len(), 2);

    let dummy_aggreg = all_circuits.prove_segment_aggregation(
        false,
        &dummy_segs[0].proof_with_pis,
        dummy_segs[0].public_values.clone(),
        false,
        &dummy_segs[1].proof_with_pis,
        dummy_segs[1].public_values.clone(),
    )?;

    let (txn_aggreg_proof, _) = all_circuits.prove_transaction_aggregation(
        false,
        &dummy_aggreg.0,
        dummy_aggreg.1,
        false,
        &second_aggreg_proof,
        second_aggreg_pv,
    )?;
    all_circuits.verify_txn_aggregation(&txn_aggreg_proof)
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
