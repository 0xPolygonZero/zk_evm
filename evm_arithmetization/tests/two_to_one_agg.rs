use std::collections::HashMap;
use std::str::FromStr;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::{AllRecursiveCircuits, AllStark, Node, StarkConfig};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

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
        &[8..17, 8..15, 8..18, 8..15, 8..10, 8..13, 8..20],
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

fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}
