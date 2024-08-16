use std::collections::HashMap;
use std::time::Duration;

use ethereum_types::{H160, H256, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    init_logger, preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
    GLOBAL_EXIT_ROOT_ACCOUNT,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use rand::random;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Execute 0 txns and 1 withdrawal.
#[test]
fn test_withdrawals() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let block_metadata = BlockMetadata {
        block_timestamp: 1.into(),
        ..BlockMetadata::default()
    };

    let (state_trie_before, storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    // Just one withdrawal.
    let withdrawals = vec![(H160(random()), U256(random()))];

    let state_trie_after = {
        let mut trie = HashedPartialTrie::from(Node::Empty);
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let addr_state_key = keccak(withdrawals[0].0);
        let addr_nibbles = Nibbles::from_bytes_be(addr_state_key.as_bytes()).unwrap();
        let account = AccountRlp {
            balance: withdrawals[0].1,
            ..AccountRlp::default()
        };
        trie.insert(addr_nibbles, rlp::encode(&account).to_vec())?;
        trie.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;
        trie.insert(
            ger_account_nibbles(),
            rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
        )?;

        trie
    };

    let trie_roots_after = TrieRoots {
        state_root: state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txns: vec![],
        withdrawals,
        global_exit_roots: vec![],
        tries: TrieInputs {
            state_trie: state_trie_before,
            transactions_trie,
            receipts_trie,
            storage_tries,
        },
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
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
