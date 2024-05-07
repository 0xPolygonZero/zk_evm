use std::collections::HashMap;
use std::{env, fs};
use std::str::FromStr;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, PublicValues, TrieRoots};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

// use std::error::Error;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type PwPIS = ProofWithPublicInputs<F,C,D>;

/// Set this to true to cache blocks in `/tmp``.  This is intended mainly for developer experience and not for CI testing.
const CACHE_TEST_BLOCKS: bool = true;


/// Get `GenerationInputs` for a simple token transfer txn, where the block has
/// the given timestamp.
fn simple_transfer(timestamp: u64) -> anyhow::Result<GenerationInputs> {
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

    let state_trie_before = Node::Leaf {
        nibbles: sender_nibbles,
        value: rlp::encode(&sender_account_before).to_vec(),
    }
    .into();

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
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
        block_gas_used: 21032.into(),
        block_bloom: [0.into(); 8],
    };

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

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

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };
    let inputs = GenerationInputs {
        signed_txn: Some(txn.to_vec()),
        withdrawals: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 21032.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    Ok(inputs)
}

fn dummy_inputs(inputs: &GenerationInputs) -> GenerationInputs {
    GenerationInputs {
        txn_number_before: inputs.txn_number_before + 1,
        gas_used_before: inputs.gas_used_after,
        gas_used_after: inputs.gas_used_after,
        signed_txn: None,
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
    }
}

#[test]
#[ignore]
fn test_two_to_one_aggregation() -> anyhow::Result<()> {
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let inputs0 = simple_transfer(1)?;
    let dummy0 = dummy_inputs(&inputs0);
    let inputs1 = simple_transfer(2)?;
    let dummy1 = dummy_inputs(&inputs1);

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);
    let (root_proof0, pv0) =
        all_circuits.prove_root(&all_stark, &config, inputs0, &mut timing, None)?;
    all_circuits.verify_root(root_proof0.clone())?;
    let (dummy_proof0, dummy_pv0) =
        all_circuits.prove_root(&all_stark, &config, dummy0, &mut timing, None)?;
    all_circuits.verify_root(dummy_proof0.clone())?;
    let (root_proof1, pv1) =
        all_circuits.prove_root(&all_stark, &config, inputs1, &mut timing, None)?;
    all_circuits.verify_root(root_proof1.clone())?;
    let (dummy_proof1, dummy_pv1) =
        all_circuits.prove_root(&all_stark, &config, dummy1, &mut timing, None)?;
    all_circuits.verify_root(dummy_proof1.clone())?;

    let (agg_proof0, pv0) = all_circuits.prove_aggregation(
        false,
        &root_proof0,
        pv0,
        false,
        &dummy_proof0,
        dummy_pv0,
    )?;
    let (agg_proof1, pv1) = all_circuits.prove_aggregation(
        false,
        &root_proof1,
        pv1,
        false,
        &dummy_proof1,
        dummy_pv1,
    )?;

    let proof = all_circuits.prove_two_to_one_aggregation(&agg_proof0, &agg_proof1, pv0, pv1)?;
    all_circuits.verify_two_to_one_aggregation(&proof)
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
    assert_eq!(checkpoint_state_trie_root, hex!("ef46022eafbc33d70e6ea9c6aef1074c1ff7ad36417ffbc64307ad3a8c274b75").into());

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
        block_gas_used: 0.into(),
        block_bloom: [0.into(); 8],
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

    let tries_after = TrieRoots {
        state_root: tries_before.state_trie.hash(),
        transactions_root: tries_before.transactions_trie.hash(),
        receipts_root: tries_before.receipts_trie.hash(),
    };
    let inputs = GenerationInputs {
        signed_txn: None,
        withdrawals: vec![],
        tries: tries_before.clone(),
        trie_roots_after: tries_after,
        contract_code,
        checkpoint_state_trie_root: tries_before.state_trie.hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    Ok(inputs)
}

fn get_test_block_proof(
    timestamp: u64,
    timing: &mut TimingTree,
    all_circuits: &AllRecursiveCircuits<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    all_stark: &AllStark<GoldilocksField, 2>,
    config: &StarkConfig,
) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
    log::info!("Stage 0");
    log::info!("Generating proof of block {}", timestamp);
    let inputs0 = empty_transfer(timestamp)?;
    let inputs = inputs0.clone();
    let dummy0 = GenerationInputs {
        txn_number_before: inputs.txn_number_before,
        gas_used_before: inputs.gas_used_after,
        gas_used_after: inputs.gas_used_after,
        signed_txn: None,
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
    };
    log::info!("{:#?}", inputs0);
    log::info!("{:#?}", dummy0);
    log::info!("Stage 1");

    let (root_proof0, pv0) = all_circuits.prove_root(&all_stark, &config, inputs0, timing, None)?;
    all_circuits.verify_root(root_proof0.clone())?;
    let (dummy_proof0, dummy_pv0) =
        all_circuits.prove_root(&all_stark, &config, dummy0, timing, None)?;
    all_circuits.verify_root(dummy_proof0.clone())?;

    log::info!("Stage 2");
    let (agg_proof0, pv0) = all_circuits.prove_aggregation(
        false,
        &root_proof0,
        pv0,
        false,
        &dummy_proof0,
        dummy_pv0,
    )?;

    log::info!("Stage 3:  Verify aggregation");
    all_circuits.verify_aggregation(&agg_proof0)?;

    log::info!("Stage 4:  Check public values");
    // Test retrieved public values from the proof public inputs.
    let retrieved_public_values0 = PublicValues::from_public_inputs(&agg_proof0.public_inputs);
    assert_eq!(retrieved_public_values0, pv0);
    assert_eq!(
        pv0.trie_roots_before.state_root,
        pv0.extra_block_data.checkpoint_state_trie_root
    );

    log::info!("Stage 5:  Prove Block");
    let (block_proof0, block_public_values) = all_circuits.prove_block(
        None, // We don't specify a previous proof, considering block 1 as the new checkpoint.
        &agg_proof0,
        pv0.clone(),
    )?;

    let pv_block = PublicValues::from_public_inputs(&block_proof0.public_inputs);
    assert_eq!(block_public_values, pv_block);

    Ok(block_proof0)
}

/// Caches proofs in `/tmp/zk_evm_test_blocks/`.
fn get_test_block_proof_cached(
    timestamp: u64,
    timing: &mut TimingTree,
    all_circuits: &AllRecursiveCircuits<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    all_stark: &AllStark<GoldilocksField, 2>,
    config: &StarkConfig,
) -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>>{
    log::info!("Getting proof of block {}", timestamp);

    // 1. Setup path
    let mut path = env::temp_dir();
    path.push("zk_evm_test");
    path.push(format!("test_block_{timestamp}.bpf"));
    log::info!("{:#?}", path);

    // 2. Read cached block from disc and return early.
    if CACHE_TEST_BLOCKS && path.try_exists()? && fs::File::open(path.clone())?.metadata()?.len() > 0 {
        let raw_block = fs::read(path)?;
        return ProofWithPublicInputs::from_bytes(
            raw_block,
            &all_circuits.block.circuit.common,
        );
    }

    // 3. Compute new block proof.
    let block_proof = get_test_block_proof(timestamp, timing, all_circuits, all_stark, config)?;
    all_circuits.verify_block(&block_proof)?;

    // 4. Write block to disc cache and validate.
    if CACHE_TEST_BLOCKS {
        // write to tmp
        let raw_block = ProofWithPublicInputs::to_bytes(&block_proof);

        if let Some(p) = path.parent() {
            fs::create_dir_all(p)?
        };
        fs::write(path.clone(), &raw_block)?;
        log::info!("Succesfully wrote blockproof to {:#?}", path);

        // Todo: move to file with `from_bytes`
        let written_block = fs::read(path.clone())?;
        assert_eq!(&raw_block, &written_block);
        let restored_block = ProofWithPublicInputs::from_bytes(
            written_block,
            &all_circuits.block.circuit.common,
        )?;
        assert_eq!(block_proof, restored_block);
        log::info!("Succesfully validated blockproof from {:#?}", path);
    }

    return Ok(block_proof);
}



#[test]
/// Run:  RUST_BACKTRACE=1 RUSTFLAGS="-Ctarget-cpu=native -g -Z threads 8"
/// cargo test --release -- --nocapture three_to_one Aggregate a sequential
/// proof containing three proofs with the structure `((A,B),C)`. We take the
/// previous example and extend it.
///
///  A    B   C
///   \  /   /
///   (A,B) /
///     \  /
///   ((A,B),C)
fn test_three_to_one_block_aggregation_ivc() -> anyhow::Result<()> {
    init_logger();
    log::info!("Meta Stage 0:  Setup");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);

    log::info!("Meta Stage 1:  Compute block proofs");
    let some_timestamps = [127, 42, 65];
    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| {
            get_test_block_proof_cached(ts, &mut timing, &all_circuits, &all_stark, &config)
        })
        .collect::<anyhow::Result<Vec<PwPIS>>>()?;

    log::info!("Meta Stage 2:  Verify block proofs");
    unrelated_block_proofs
        .iter()
        .map(|bp| all_circuits.verify_block(bp)).collect::<anyhow::Result<()>>()?;

    log::info!("Meta Stage 3:  Aggregate block proofs");
    let bp = unrelated_block_proofs;

    // let aggproof0 = all_circuits.prove_two_to_one_block_ivc(None, &bp[0])?;
    // all_circuits.verify_two_to_one_block_ivc(&aggproof0)?;

    // let aggproof01 = all_circuits.prove_two_to_one_block_ivc(Some(&aggproof0), &bp[1])?;
    // all_circuits.verify_two_to_one_block_ivc(&aggproof01)?;

    // let aggproof012 = all_circuits.prove_two_to_one_block_ivc(Some(&aggproof01), &bp[2])?;
    // all_circuits.verify_two_to_one_block_ivc(&aggproof012)?;
    assert!(false, "Hoooray!!, 3-block aggregation was verified");
    Ok(())
}



/// Run:  RUST_BACKTRACE=1 RUSTFLAGS="-Ctarget-cpu=native -g -Z threads 8"
/// cargo test --release -- --nocapture four_to_one
/// Aggregate a sequential /// proof containing three proofs with the structure `((A,B),(C,D))`.
///
///  A    B    C    D    Blockproofs (base case)
///   \  /      \  /
///  (A, B)    (C, D)    Two-to-one block aggregation proofs
///     \       /
///   ((A,B), (C,D))     Two-to-one block aggregation proofs
#[test]
fn test_block_aggregation_binop_4_blocks() -> anyhow::Result<()> {
    init_logger();
    log::info!("Meta Stage 0:  Setup");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);

    log::info!("Meta Stage 1:  Compute block proofs");
    let some_timestamps = [127, 42, 65, 43];
    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| {
            get_test_block_proof_cached(ts, &mut timing, &all_circuits, &all_stark, &config)
        })
        .collect::<anyhow::Result<Vec<PwPIS>>>()?;

    log::info!("Meta Stage 2:  Verify block proofs");
    unrelated_block_proofs
        .iter()
        .map(|bp| all_circuits.verify_block(bp)).collect::<anyhow::Result<()>>()?;

    log::info!("Meta Stage 3:  Aggregate block proofs");
    let bp = unrelated_block_proofs;

    let aggproof01 = all_circuits.prove_two_to_one_block_binop(&bp[0], false, &bp[1], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof01)?;

    let aggproof23 = all_circuits.prove_two_to_one_block_binop(&bp[2], false, &bp[3], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof23)?;

    let aggproof0123 = all_circuits.prove_two_to_one_block_binop(&aggproof01, true, &aggproof23, true)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof0123)?;

    Ok(())
}



#[test]
fn test_block_aggregation_binop_same_block_twice() -> anyhow::Result<()> {
    init_logger();
    log::info!("Meta Stage 0:  Setup");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);

    log::info!("Meta Stage 1:  Compute block proofs");
    let some_timestamps = [42, 42];
    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| {
            get_test_block_proof_cached(ts, &mut timing, &all_circuits, &all_stark, &config)
        })
        .collect::<anyhow::Result<Vec<PwPIS>>>()?;

    log::info!("Meta Stage 2:  Verify block proofs");
    unrelated_block_proofs
        .iter()
        .map(|bp| all_circuits.verify_block(bp)).collect::<anyhow::Result<()>>()?;

    log::info!("Meta Stage 3:  Aggregate block proofs");
    let bp = unrelated_block_proofs;

    let aggproof_42_42 = all_circuits.prove_two_to_one_block_binop(&bp[0], false, &bp[1], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof_42_42)?;

    Ok(())
}


/// Run:  RUST_BACKTRACE=1 RUSTFLAGS="-Ctarget-cpu=native -g -Z threads 8"
/// cargo test --release -- --nocapture four_to_one
/// Aggregate a sequential /// proof containing three proofs with the structure `((A,B),(C,D))`.
///
///  A    B    C     Blockproofs (base case)
///   \  /    /
///  (A, B)  /       Two-to-one block aggregation proofs
///     \   /
///  ((A,B), C)     Two-to-one block aggregation proofs
#[test]
fn test_block_aggregation_binop_foldleft() -> anyhow::Result<()> {
    init_logger();
    log::info!("Meta Stage 0:  Setup");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);

    log::info!("Meta Stage 1:  Compute block proofs");
    let some_timestamps = [65, 127, 42];
    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| {
            get_test_block_proof_cached(ts, &mut timing, &all_circuits, &all_stark, &config)
        })
        .collect::<anyhow::Result<Vec<PwPIS>>>()?;

    log::info!("Meta Stage 2:  Verify block proofs");
    unrelated_block_proofs
        .iter()
        .map(|bp| all_circuits.verify_block(bp)).collect::<anyhow::Result<()>>()?;

    log::info!("Meta Stage 3:  Aggregate block proofs");
    let bp = unrelated_block_proofs;

    let aggproof01 = all_circuits.prove_two_to_one_block_binop(&bp[0], false, &bp[1], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof01)?;

    let aggproof012 = all_circuits.prove_two_to_one_block_binop(&aggproof01, true, &bp[2], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof012)?;

    Ok(())
}


///
///  A    B    C    Blockproofs (base case)
///   \   \   /
///    \  (B,C)     Two-to-one block aggregation proofs
///     \  /
///  (A,(B, C))     Two-to-one block aggregation proofs
#[test]
fn test_block_aggregation_binop_foldright() -> anyhow::Result<()> {
    init_logger();
    log::info!("Meta Stage 0:  Setup");
    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    // Preprocess all circuits.
    let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
        &all_stark,
        &[16..17, 9..15, 12..18, 14..15, 9..10, 12..13, 17..20],
        &config,
    );

    let mut timing = TimingTree::new("prove root first", log::Level::Info);

    log::info!("Meta Stage 1:  Compute block proofs");
    let some_timestamps = [65, 127, 42];
    let unrelated_block_proofs = some_timestamps
        .iter()
        .map(|&ts| {
            get_test_block_proof_cached(ts, &mut timing, &all_circuits, &all_stark, &config)
        })
        .collect::<anyhow::Result<Vec<PwPIS>>>()?;

    log::info!("Meta Stage 2:  Verify block proofs");
    unrelated_block_proofs
        .iter()
        .map(|bp| all_circuits.verify_block(bp)).collect::<anyhow::Result<()>>()?;

    log::info!("Meta Stage 3:  Aggregate block proofs");
    let bp = unrelated_block_proofs;

    let aggproof12 = all_circuits.prove_two_to_one_block_binop(&bp[1], false, &bp[2], false)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof12)?;

    let aggproof012 = all_circuits.prove_two_to_one_block_binop(&bp[0], false, &aggproof12, true)?;
    all_circuits.verify_two_to_one_block_binop(&aggproof012)?;

    Ok(())
}









fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
