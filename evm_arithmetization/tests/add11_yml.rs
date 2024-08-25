use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::TrieInputs;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    init_logger, preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
    GLOBAL_EXIT_ROOT_ACCOUNT,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::StarkConfig;
use evm_arithmetization::{AllStark, GenerationInputs, Node};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;

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

    let (mut state_trie_before, mut storage_tries) =
        preinitialized_state_and_storage_tries().unwrap();
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before
        .insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_before).to_vec(),
        )
        .unwrap();
    state_trie_before
        .insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())
        .unwrap();
    state_trie_before
        .insert(to_nibbles, rlp::encode(&to_account_before).to_vec())
        .unwrap();

    storage_tries.push((to_hashed, Node::Empty.into()));

    let tries_before = TrieInputs {
        state_trie: state_trie_before.clone(),
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries,
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
        ..Default::default()
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let expected_state_trie_after = {
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )
        .unwrap();
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

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
        expected_state_trie_after
            .insert(
                beneficiary_nibbles,
                rlp::encode(&beneficiary_account_after).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(to_nibbles, rlp::encode(&to_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(
                beacon_roots_account_nibbles(),
                rlp::encode(&beacon_roots_account).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(
                ger_account_nibbles(),
                rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: 0xa868u64.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie
        .insert(
            Nibbles::from_str("0x80").unwrap(),
            rlp::encode(&receipt_0).to_vec(),
        )
        .unwrap();
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
        global_exit_roots: vec![],
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
