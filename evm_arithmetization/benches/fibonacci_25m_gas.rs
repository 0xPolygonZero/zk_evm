//! Benchmarks the CPU execution of a transaction calling a simple Fibonacci
//! contract, iterating over and over until reaching the 25M gas limit.
//!
//! Total number of user instructions: 7_136_858.
//! Total number of loops: 2_378_952.

use std::collections::HashMap;
use std::str::FromStr;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, H256, U256};
use evm_arithmetization::cpu::kernel::aggregator::KERNEL;
use evm_arithmetization::cpu::kernel::opcodes::{get_opcode, get_push_opcode};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
    GLOBAL_EXIT_ROOT_ACCOUNT,
};
use evm_arithmetization::Node;
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;

type F = GoldilocksField;

fn criterion_benchmark(c: &mut Criterion) {
    let inputs = prepare_setup().unwrap();

    // Dummy call to preinitialize the kernel.
    let _ = KERNEL.hash();

    let mut group = c.benchmark_group("fibonacci_25m_gas");
    group.sample_size(10);
    group.bench_function(BenchmarkId::from_parameter(8), |b| {
        b.iter_batched(
            || inputs.clone(),
            |inp| simulate_execution::<F>(inp).unwrap(),
            BatchSize::LargeInput,
        )
    });

    // Last run to print the number of CPU cycles.
    init_logger();
    simulate_execution::<F>(inputs).unwrap();
}

fn prepare_setup() -> anyhow::Result<GenerationInputs> {
    let sender = hex!("8943545177806ED17B9F23F0a21ee5948eCaa776");
    let to = hex!("159271B89fea49aF29DFaf8b4eCE7D042D5d6f07");

    let sender_state_key = keccak(sender);
    let to_state_key = keccak(to);

    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_state_key.as_bytes()).unwrap();

    let push1 = get_push_opcode(1);
    let push4 = get_push_opcode(4);
    let add = get_opcode("ADD");
    let swap1 = get_opcode("SWAP1");
    let dup2 = get_opcode("DUP2");
    let jump = get_opcode("JUMP");
    let jumpdest = get_opcode("JUMPDEST");
    let code = [
        push1, 1, push1, 1, jumpdest, dup2, add, swap1, push4, 0, 0, 0, 4, jump,
    ];
    let code_hash = keccak(code);

    let empty_trie_root = HashedPartialTrie::from(Node::Empty).hash();

    let sender_account_before = AccountRlp {
        nonce: 169.into(),
        balance: U256::from_dec_str("999999999998417410153631615")?,
        storage_root: empty_trie_root,
        code_hash: keccak(vec![]),
    };
    let to_account_before = AccountRlp {
        nonce: 1.into(),
        balance: 0.into(),
        storage_root: empty_trie_root,
        code_hash,
    };

    let (mut state_trie_before, mut storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before.insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())?;
    state_trie_before.insert(to_nibbles, rlp::encode(&to_account_before).to_vec())?;

    storage_tries.push((sender_state_key, Node::Empty.into()));
    storage_tries.push((to_state_key, Node::Empty.into()));

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries,
    };

    let gas_used = U256::from(0x17d7840_u32);

    let txn = hex!("f86981a9843b9aca1084017d784094159271b89fea49af29dfaf8b4ece7d042d5d6f0780808360306ba00cdea08ac2e8075188b289d779fa84bf86020c2b162bbee11d2785b5225b0ccca00ea9a76f4641955a74ae8c1589914fc7d6c5bfe5940454a89daf5b12d6f06617");
    let value = U256::zero();

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(sender),
        block_number: 0x176.into(),
        block_chain_id: 0x301824.into(),
        block_timestamp: 0x664e63af.into(),
        block_gaslimit: 0x1c9c380.into(),
        block_gas_used: gas_used,
        block_base_fee: 0x11.into(),
        block_random: H256(hex!(
            "388bd2892c01ab13e22f713316cc2b5d3c3d963e1426c25a80c7878a1815f889"
        )),
        ..Default::default()
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let sender_account_after = AccountRlp {
        balance: sender_account_before.balance - value - gas_used * block_metadata.block_base_fee,
        nonce: sender_account_before.nonce + 1,
        ..sender_account_before
    };
    let to_account_after = to_account_before;

    let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
    expected_state_trie_after
        .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())?;
    expected_state_trie_after.insert(to_nibbles, rlp::encode(&to_account_after).to_vec())?;

    update_beacon_roots_account_storage(
        &mut beacon_roots_account_storage,
        block_metadata.block_timestamp,
        block_metadata.parent_beacon_block_root,
    )?;
    let beacon_roots_account = beacon_roots_contract_from_storage(&beacon_roots_account_storage);
    expected_state_trie_after.insert(
        beacon_roots_account_nibbles(),
        rlp::encode(&beacon_roots_account).to_vec(),
    )?;
    expected_state_trie_after.insert(
        ger_account_nibbles(),
        rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
    )?;

    let receipt_0 = LegacyReceiptRlp {
        status: false,
        cum_gas_used: gas_used,
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

    Ok(GenerationInputs {
        signed_txns: vec![txn.to_vec()],
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: H256(hex!(
            "fe07ff6d1ab215df17884b89112ccf2373597285a56c5902150313ad1a53ee57"
        )),
        global_exit_roots: vec![],
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: gas_used,
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    })
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
