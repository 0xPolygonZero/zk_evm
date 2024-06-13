//! Benchmarks the CPU execution of a transaction calling a simple Fibonacci
//! contract, iterating over and over until reaching the 25M gas limit.
//!
//! Total number of user instructions: 7_136_858.
//! Total number of loops: 2_378_952.

use std::collections::HashMap;
use std::str::FromStr;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H160, H256, U256};
use evm_arithmetization::cpu::kernel::aggregator::KERNEL;
use evm_arithmetization::cpu::kernel::opcodes::{get_opcode, get_push_opcode};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::Node;
use hex_literal::hex;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use smt_trie::code::hash_bytecode_u256;
use smt_trie::db::{Db, MemoryDb};
use smt_trie::keys::{key_balance, key_code, key_code_length, key_nonce, key_storage};
use smt_trie::smt::Smt;
use smt_trie::utils::hashout2u;

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
    let code_hash = hash_bytecode_u256(code.to_vec());

    let sender_account_before = AccountRlp {
        nonce: 169.into(),
        balance: U256::from_dec_str("999999999998417410153631615")?,
        code_hash: hash_bytecode_u256(vec![]),
        code_length: 0.into(),
    };
    let to_account_before = AccountRlp {
        nonce: 1.into(),
        balance: 0.into(),
        code_hash,
        code_length: code.len().into(),
    };

    let mut state_smt_before = Smt::<MemoryDb>::default();
    set_account(
        &mut state_smt_before,
        H160(sender),
        &sender_account_before,
        &HashMap::new(),
    );
    set_account(
        &mut state_smt_before,
        H160(to),
        &to_account_before,
        &HashMap::new(),
    );

    let tries_before = TrieInputs {
        state_smt: state_smt_before.serialize(),
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
    };

    let gas_used = U256::from(0x17d7840_u32);

    let txn = hex!("f86981a9843b9aca1084017d784094159271b89fea49af29dfaf8b4ece7d042d5d6f0780808360306ba00cdea08ac2e8075188b289d779fa84bf86020c2b162bbee11d2785b5225b0ccca00ea9a76f4641955a74ae8c1589914fc7d6c5bfe5940454a89daf5b12d6f06617");
    let value = U256::zero();

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(sender),
        block_difficulty: 0x0.into(),
        block_number: 0x176.into(),
        block_chain_id: 0x301824.into(),
        block_timestamp: 0x664e63af.into(),
        block_gaslimit: 0x1c9c380.into(),
        block_gas_used: gas_used,
        block_bloom: [0.into(); 8],
        block_base_fee: 0x11.into(),
        block_random: H256(hex!(
            "388bd2892c01ab13e22f713316cc2b5d3c3d963e1426c25a80c7878a1815f889"
        )),
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(hash_bytecode_u256(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let sender_account_after = AccountRlp {
        balance: sender_account_before.balance - value - gas_used * block_metadata.block_base_fee,
        nonce: sender_account_before.nonce + 1,
        ..sender_account_before
    };
    let to_account_after = to_account_before;

    let mut expected_state_smt_after = Smt::<MemoryDb>::default();
    set_account(
        &mut expected_state_smt_after,
        H160(sender),
        &sender_account_after,
        &HashMap::new(),
    );
    set_account(
        &mut expected_state_smt_after,
        H160(to),
        &to_account_after,
        &HashMap::new(),
    );

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
        state_root: H256::from_uint(&hashout2u(expected_state_smt_after.root)),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    Ok(GenerationInputs {
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: H256(hex!(
            "fe07ff6d1ab215df17884b89112ccf2373597285a56c5902150313ad1a53ee57"
        )),
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

fn set_account<D: Db>(
    smt: &mut Smt<D>,
    addr: Address,
    account: &AccountRlp,
    storage: &HashMap<U256, U256>,
) {
    smt.set(key_balance(addr), account.balance);
    smt.set(key_nonce(addr), account.nonce);
    smt.set(key_code(addr), account.code_hash);
    smt.set(key_code_length(addr), account.code_length);
    for (&k, &v) in storage {
        smt.set(key_storage(addr, k), v);
    }
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
