use std::collections::HashMap;

use ethereum_types::U256;
use keccak_hash::keccak;
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use mpt_trie::partial_trie::PartialTrie;
use plonky2::field::goldilocks_field::GoldilocksField as F;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::generation::state::State;
use crate::generation::TrieInputs;
use crate::generation::NUM_EXTRA_CYCLES_AFTER;
use crate::generation::NUM_EXTRA_CYCLES_BEFORE;
use crate::proof::BlockMetadata;
use crate::proof::TrieRoots;
use crate::witness::state::RegistersState;
use crate::{proof::BlockHashes, GenerationInputs, Node};

// Test to check NUM_EXTRA_CYCLES_BEFORE and NUM_EXTRA_CYCLES_AFTER
#[test]
fn test_init_exc_stop() {
    let block_metadata = BlockMetadata {
        block_number: 1.into(),
        ..Default::default()
    };

    let state_trie = HashedPartialTrie::from(Node::Empty);
    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);
    let storage_tries = vec![];

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);

    // No transactions, so no trie roots change.
    let trie_roots_after = TrieRoots {
        state_root: state_trie.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txns: vec![],
        withdrawals: vec![],
        tries: TrieInputs {
            state_trie,
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
    let initial_stack = vec![];
    let initial_offset = KERNEL.global_labels["init"];
    let mut interpreter: Interpreter<F> =
        Interpreter::new_with_generation_inputs(initial_offset, initial_stack, &inputs, None);
    interpreter.halt_offsets = vec![KERNEL.global_labels["main"]];
    interpreter.set_is_kernel(true);
    interpreter.run().expect("Running dummy init failed.");

    assert_eq!(
        interpreter.get_clock(),
        NUM_EXTRA_CYCLES_BEFORE,
        "NUM_EXTRA_CYCLES_BEFORE is set incorrectly."
    );

    // The registers should not have changed, besides the stack top.
    let expected_registers = RegistersState {
        stack_top: interpreter.get_registers().stack_top,
        check_overflow: interpreter.get_registers().check_overflow,
        ..RegistersState::new()
    };

    assert_eq!(
        interpreter.get_registers(),
        expected_registers,
        "Incorrect registers for dummy run."
    );

    let main_offset = KERNEL.global_labels["main"];
    let mut interpreter: Interpreter<F> =
        Interpreter::new_dummy_with_generation_inputs(initial_offset, vec![], &inputs);
    interpreter.halt_offsets = vec![KERNEL.global_labels["halt_final"]];
    interpreter.set_is_kernel(true);
    interpreter.clock = 0;
    interpreter.run().expect("Running dummy exc_stop failed.");

    // The "-1" comes from the fact that we stop 1 cycle before the max, to allow
    // for one padding row, which is needed for CPU STARK.
    assert_eq!(
        interpreter.get_clock(),
        NUM_EXTRA_CYCLES_BEFORE + NUM_EXTRA_CYCLES_AFTER - 1,
        "NUM_EXTRA_CYCLES_AFTER is set incorrectly."
    );
}
