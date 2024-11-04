use anyhow::Result;
use ethereum_types::{BigEndianHash, H256};
use plonky2::field::goldilocks_field::GoldilocksField as F;

use super::get_state_world_no_storage;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::INITIAL_RLP_ADDR;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::initialize_mpts;
use crate::cpu::kernel::tests::mpt::{extension_to_leaf, test_account_1_rlp, test_account_2_rlp};
use crate::generation::TrieInputs;
use crate::world::world::World;
use crate::Node;

// TODO: Test with short leaf. Might need to be a storage trie.

#[test]
fn mpt_hash_empty() -> Result<()> {
    let trie_inputs = TrieInputs {
        state_trie: Default::default(),
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };

    test_state_trie(trie_inputs)
}

#[test]
fn mpt_hash_empty_branch() -> Result<()> {
    let children = core::array::from_fn(|_| Node::Empty.into());
    let state_trie = get_state_world_no_storage(
        Node::Branch {
            children,
            value: vec![],
        }
        .into(),
    );
    let trie_inputs = TrieInputs {
        state_trie,
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };
    test_state_trie(trie_inputs)
}

#[test]
fn mpt_hash_hash() -> Result<()> {
    let hash = H256::random();

    let state_trie = get_state_world_no_storage(Node::Hash(hash).into());
    let trie_inputs = TrieInputs {
        state_trie,
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };

    test_state_trie(trie_inputs)
}

#[test]
fn mpt_hash_leaf() -> Result<()> {
    let state_trie = get_state_world_no_storage(
        Node::Leaf {
            nibbles: 0xABC_u64.into(),
            value: test_account_1_rlp(),
        }
        .into(),
    );
    let trie_inputs = TrieInputs {
        state_trie,
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };
    test_state_trie(trie_inputs)
}

#[test]
fn mpt_hash_extension_to_leaf() -> Result<()> {
    let state_trie = get_state_world_no_storage(extension_to_leaf(test_account_1_rlp()));
    let trie_inputs = TrieInputs {
        state_trie,
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };
    test_state_trie(trie_inputs)
}

#[test]
fn mpt_hash_branch_to_leaf() -> Result<()> {
    let leaf = Node::Leaf {
        nibbles: 0xABC_u64.into(),
        value: test_account_2_rlp(),
    }
    .into();

    let mut children = core::array::from_fn(|_| Node::Empty.into());
    children[3] = leaf;
    let state_trie = get_state_world_no_storage(
        Node::Branch {
            children,
            value: vec![],
        }
        .into(),
    );

    let trie_inputs = TrieInputs {
        state_trie,
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        // storage_tries: vec![],
    };

    test_state_trie(trie_inputs)
}

fn test_state_trie(trie_inputs: TrieInputs) -> Result<()> {
    let mpt_hash_state_trie = KERNEL.global_labels["mpt_hash_state_trie"];

    let initial_stack = vec![];
    let mut interpreter: Interpreter<F> = Interpreter::new(0, initial_stack, None);

    initialize_mpts(&mut interpreter, &trie_inputs);
    assert_eq!(interpreter.stack(), vec![]);

    // Now, execute `mpt_hash_state_trie`.
    interpreter.generation_state.registers.program_counter = mpt_hash_state_trie;
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(1.into()) // Initial length of the trie data segment, unused.
        .expect("The stack should not overflow");
    interpreter
        .push(INITIAL_RLP_ADDR.1.into()) // rlp_start
        .expect("The stack should not overflow.");
    interpreter.run()?;

    assert_eq!(
        interpreter.stack().len(),
        2,
        "Expected 2 items on stack, found {:?}",
        interpreter.stack()
    );
    let hash = H256::from_uint(&interpreter.stack()[1]);
    let expected_state_trie_hash = trie_inputs.state_trie.state.unwrap_left().root();
    assert_eq!(hash, expected_state_trie_hash);

    Ok(())
}
