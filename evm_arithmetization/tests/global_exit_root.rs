use std::collections::HashMap;
use std::time::Duration;

use ethereum_types::{H256, U256};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::prove;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    ger_contract_from_storage, init_logger, preinitialized_state_and_storage_tries,
    update_beacon_roots_account_storage, update_ger_account_storage,
};
use evm_arithmetization::verifier::verify_proof;
use evm_arithmetization::{AllStark, Node, StarkConfig};
use keccak_hash::keccak;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use rand::random;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Add a new Global Exit Root to the state trie.
#[test]
fn test_global_exit_root() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let block_metadata = BlockMetadata {
        block_timestamp: 1.into(),
        ..BlockMetadata::default()
    };

    let (state_trie_before, storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    let mut ger_account_storage = storage_tries[1].1.clone();
    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    let global_exit_roots = vec![(U256(random()), H256(random()))];

    let state_trie_after = {
        let mut trie = HashedPartialTrie::from(Node::Empty);
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);
        for &(timestamp, root) in &global_exit_roots {
            update_ger_account_storage(&mut ger_account_storage, root, timestamp)?;
        }
        let ger_account = ger_contract_from_storage(&ger_account_storage);

        trie.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;
        trie.insert(ger_account_nibbles(), rlp::encode(&ger_account).to_vec())?;

        trie
    };

    let trie_roots_after = TrieRoots {
        state_root: state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txn: None,
        withdrawals: vec![],
        global_exit_roots,
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
        jumpdest_table: Default::default(),
    };

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing, None)?;
    timing.filter(Duration::from_millis(100)).print();

    verify_proof(&all_stark, proof, &config)
}
