use std::collections::{BTreeMap, HashMap};

use either::Either;
use ethereum_types::{BigEndianHash, U256};
use keccak_hash::{keccak, H256};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;
use smt_trie::{code::hash_bytecode_u256, utils::hashout2u};

use crate::cpu::kernel::{aggregator::KERNEL, interpreter::Interpreter};
use crate::generation::{
    state::State, TrieInputs, NUM_EXTRA_CYCLES_AFTER, NUM_EXTRA_CYCLES_BEFORE,
};
use crate::memory::segments::Segment;
use crate::testing_utils::init_logger;
#[cfg(feature = "eth_mainnet")]
use crate::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage,
    preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
};
use crate::witness::{memory::MemoryAddress, state::RegistersState};
use crate::world::tries::{StateMpt, StorageTrie};
use crate::world::world::{StateWorld, Type1World};
use crate::EMPTY_CONSOLIDATED_BLOCKHASH;
use crate::{
    proof::{BlockHashes, BlockMetadata, TrieRoots},
    GenerationInputs, Node,
};

enum RegistersIdx {
    ProgramCounter = 0,
    IsKernel = 1,
    _StackLen = 2,
    _StackTop = 3,
    _Context = 4,
    _GasUsed = 5,
}

const REGISTERS_LEN: usize = 6;

// Test to check NUM_EXTRA_CYCLES_BEFORE and NUM_EXTRA_CYCLES_AFTER
#[test]
fn test_init_exc_stop() {
    init_logger();

    let block_metadata = BlockMetadata {
        block_number: 1.into(),
        block_timestamp: 0x1234.into(),
        ..Default::default()
    };

    let state_trie_before = StateWorld::default();

    let transactions_trie = HashedPartialTrie::from(Node::Empty);
    let receipts_trie = HashedPartialTrie::from(Node::Empty);

    let mut expected_state_trie_after = StateWorld::default();
    #[cfg(feature = "eth_mainnet")]
    let (state_trie_before_hashed, storage_tries) =
        preinitialized_state_and_storage_tries().unwrap();
    #[cfg(feature = "eth_mainnet")]
    {
        let mut type1world = Type1World::new(
            StateMpt::new_with_inner(state_trie_before_hashed),
            BTreeMap::default(),
        )
        .unwrap();
        let mut init_storage = BTreeMap::default();
        for (storage, v) in &storage_tries {
            init_storage.insert(*storage, StorageTrie::new_with_trie(v.clone()));
        }
        type1world.set_storage(init_storage);
    }

    #[cfg(feature = "eth_mainnet")]
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    #[cfg(feature = "eth_mainnet")]
    {
        expected_state_trie_after = {
            update_beacon_roots_account_storage(
                &mut beacon_roots_account_storage,
                block_metadata.block_timestamp,
                block_metadata.parent_beacon_block_root,
            )
            .unwrap();
            let beacon_roots_account =
                beacon_roots_contract_from_storage(&beacon_roots_account_storage);

            let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
            expected_state_trie_after
                .insert(
                    beacon_roots_account_nibbles(),
                    rlp::encode(&beacon_roots_account).to_vec(),
                )
                .unwrap();
            let mut type1world = Type1World::new(
                StateMpt::new_with_inner(expected_state_trie_after),
                BTreeMap::default(),
            )
            .unwrap();
            let mut init_storage = BTreeMap::default();
            for (storage, v) in storage_tries {
                init_storage.insert(storage, StorageTrie::new_with_trie(v));
            }
            type1world.set_storage(init_storage);
            StateWorld {
                state: Either::Left(type1world),
            }
        };
    }

    let mut contract_code = HashMap::new();

    let contract_hash = if cfg!(feature = "eth_mainnet") {
        Either::Left(keccak(vec![]))
    } else {
        Either::Right(hash_bytecode_u256(vec![]))
    };
    contract_code.insert(contract_hash, vec![]);

    let state_root = match &expected_state_trie_after.state {
        Either::Left(type1world) => type1world.state_trie().hash(),
        Either::Right(type2world) => H256::from_uint(&hashout2u(type2world.as_smt().root)),
    };
    let trie_roots_after = TrieRoots {
        state_root,
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs {
        signed_txns: vec![],
        burn_addr: None,
        withdrawals: vec![],
        tries: TrieInputs {
            state_trie: state_trie_before,
            transactions_trie,
            receipts_trie,
        },
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        checkpoint_consolidated_hash: EMPTY_CONSOLIDATED_BLOCKHASH.map(F::from_canonical_u64),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: 0.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
        ger_data: None,
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

    let exc_stop_offset = KERNEL.global_labels["exc_stop"];

    let pc_u256 = U256::from(interpreter.get_registers().program_counter);
    let exit_info = pc_u256 + (U256::one() << 32);
    interpreter.push(exit_info).unwrap();
    interpreter.get_mut_registers().program_counter = exc_stop_offset;
    interpreter.halt_offsets = vec![KERNEL.global_labels["halt_final"]];
    interpreter.set_is_kernel(true);
    interpreter.clock = 0;

    // Set the program counter and `is_kernel` at the end of the execution. The
    // `registers_before` and `registers_after` are stored contiguously in the
    // `RegistersState` segment. We need to update `registers_after` here, hence the
    // offset by `RegistersData::SIZE`.
    let regs_to_set = [
        (
            MemoryAddress {
                context: 0,
                segment: Segment::RegistersStates.unscale(),
                virt: REGISTERS_LEN + RegistersIdx::ProgramCounter as usize,
            },
            pc_u256,
        ),
        (
            MemoryAddress {
                context: 0,
                segment: Segment::RegistersStates.unscale(),
                virt: REGISTERS_LEN + RegistersIdx::IsKernel as usize,
            },
            U256::one(),
        ),
    ];
    interpreter.set_memory_multi_addresses(&regs_to_set);

    interpreter.run().expect("Running dummy exc_stop failed.");

    // The "-2" comes from the fact that:
    // - we stop 1 cycle before the max, to allow for one padding row, which is
    //   needed for CPU STARK.
    // - we need one additional cycle to enter `exc_stop`.
    assert_eq!(
        interpreter.get_clock(),
        NUM_EXTRA_CYCLES_AFTER - 2,
        "NUM_EXTRA_CYCLES_AFTER is set incorrectly."
    );
}
