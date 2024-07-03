use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::prove;
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::verifier::verify_proof;
use evm_arithmetization::{AllStark, Node, StarkConfig};
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

/// The `add11_yml` test case from https://github.com/ethereum/tests
#[test]
fn add11_yml() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

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
    )?;
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())?;
    state_trie_before.insert(to_nibbles, rlp::encode(&to_account_before).to_vec())?;

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
        )?;
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())?;
        expected_state_trie_after.insert(to_nibbles, rlp::encode(&to_account_after).to_vec())?;
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
    )?;
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
    let _inputs = GenerationInputs {
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
    };

    let good = vec![
        248, 74, 1, 134, 15, 255, 255, 251, 152, 107, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255,
        131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227,
        99, 180, 33, 160, 197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192,
        229, 0, 182, 83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
    ];
    let good: AccountRlp = rlp::decode(&good).unwrap();
    log::debug!("good = {:#?}", good);
    let bad = vec![
        248, 74, 134, 16, 0, 0, 0, 0, 0, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69,
        230, 146, 192, 248, 110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180,
        33, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let bad: AccountRlp = rlp::decode(&bad).unwrap();
    log::debug!("bad = {:#?}", bad);

    let dir = Path::new("/Users/agonzalez/evm-tests-suite-parsed/serialized_tests//stExample/basefeeExample_d0g0v0_Shanghai.json");
    visit_dirs(dir)?;
    // let bytes =
    // std::fs::read("/Users/agonzalez/evm-tests-suite-parsed/serialized_tests/
    // stTimeConsuming/static_Call50000_sha256_d0g0v0_Shanghai.json").unwrap();
    //             let inputs = serde_json::from_slice(&bytes).unwrap();

    //             let mut timing = TimingTree::new("prove", log::Level::Debug);
    //             // let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut
    // timing,             // None)?;
    //             simulate_execution::<F>(inputs)?;
    //             timing.filter(Duration::from_millis(100)).print();

    Ok(())
    // verify_proof(&all_stark, proof, &config)
}

fn visit_dirs(dir: &Path) -> anyhow::Result<()> {
    if dir == Path::new("/Users/agonzalez/evm-tests-suite-parsed/serialized_tests/stTimeConsuming")
    {
        return Ok(());
    }
    if dir.is_dir() {
        log::info!("Found directory: {:?}", dir);
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            visit_dirs(&path)?; // Recurse into the subdirectory
        }
    } else if dir.is_file() {
        log::info!("Found file: {:?}", dir);
        let bytes = std::fs::read(dir).unwrap();
        let inputs = serde_json::from_slice(&bytes).unwrap();

        let mut timing = TimingTree::new("prove", log::Level::Debug);
        // let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing,
        // None)?;
        simulate_execution::<F>(inputs)?;
        timing.filter(Duration::from_millis(100)).print();
    }
    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
