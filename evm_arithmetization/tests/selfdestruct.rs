#![cfg(feature = "eth_mainnet")]

use std::str::FromStr;
use std::time::Duration;

use ethereum_types::{Address, BigEndianHash, H256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, init_logger,
    preinitialized_state_and_storage_tries, update_beacon_roots_account_storage, TEST_STARK_CONFIG,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::{AllStark, Node, StarkConfig, EMPTY_CONSOLIDATED_BLOCKHASH};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use zk_evm_common::eth_to_wei;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

/// Test a simple selfdestruct.
#[test]
fn test_selfdestruct() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = TEST_STARK_CONFIG;

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let sender = hex!("5eb96AA102a29fAB267E12A40a5bc6E9aC088759");
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
    let code = vec![
        0x32, // ORIGIN
        0xFF, // SELFDESTRUCT
    ];
    let to_account_before = AccountRlp {
        nonce: 12.into(),
        balance: eth_to_wei(10_000.into()),
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: keccak(&code),
    };

    let (mut state_trie_before, storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())?;
    state_trie_before.insert(to_nibbles, rlp::encode(&to_account_before).to_vec())?;

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        storage_tries,
    };

    // Generated using a little py-evm script.
    let txn = hex!("f868050a831e848094a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0880de0b6b3a76400008025a09bab8db7d72e4b42cba8b117883e16872966bae8e4570582de6ed0065e8c36a1a01256d44d982c75e0ab7a19f61ab78afa9e089d51c8686fdfbee085a5ed5d8ff8");

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: 26002.into(),
        ..Default::default()
    };

    let contract_code = [(keccak(&code), code.clone()), (keccak([]), vec![])].into();

    let expected_state_trie_after: HashedPartialTrie = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);

        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let sender_account_after = AccountRlp {
            nonce: 6.into(),
            balance: eth_to_wei(110_000.into()) - 26_002 * 0xa,
            storage_root: HashedPartialTrie::from(Node::Empty).hash(),
            code_hash: keccak([]),
        };
        state_trie_after.insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())?;

        // EIP-6780: The account won't be deleted because it wasn't created during this
        // transaction.
        let to_account_before = AccountRlp {
            nonce: 12.into(),
            balance: 0.into(),
            storage_root: HashedPartialTrie::from(Node::Empty).hash(),
            code_hash: keccak(&code),
        };
        state_trie_after.insert(to_nibbles, rlp::encode(&to_account_before).to_vec())?;
        state_trie_after.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;

        state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: 26002.into(),
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

    let inputs = GenerationInputs::<F> {
        signed_txns: vec![txn.to_vec()],
        burn_addr: None,
        withdrawals: vec![],
        ger_data: None,
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        checkpoint_consolidated_hash: EMPTY_CONSOLIDATED_BLOCKHASH.map(F::from_canonical_u64),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 26002.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

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
