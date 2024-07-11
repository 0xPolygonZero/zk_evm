use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use ethereum_types::{BigEndianHash, H256};
use mpt_trie::nibbles::{Nibbles, NibblesIntern};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::random;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::initialize_mpts;
use crate::cpu::kernel::tests::mpt::{nibbles_64, test_account_1_rlp, test_account_2};
use crate::generation::mpt::AccountRlp;
use crate::generation::state::State;
use crate::generation::TrieInputs;
use crate::memory::segments::Segment;
use crate::util::h2u;
use crate::Node;

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
}

#[test]
fn mpt_delete_empty() -> Result<()> {
    init_logger();
    test_state_trie(Default::default(), nibbles_64(0xABC), test_account_2())
}

#[test]
fn mpt_delete_leaf_nonoverlapping_keys() -> Result<()> {
    let state_trie = Node::Leaf {
        nibbles: nibbles_64(0xABC),
        value: test_account_1_rlp(),
    }
    .into();
    test_state_trie(state_trie, nibbles_64(0x123), test_account_2())
}

#[test]
fn mpt_delete_leaf_overlapping_keys() -> Result<()> {
    let state_trie = Node::Leaf {
        nibbles: nibbles_64(0xABC),
        value: test_account_1_rlp(),
    }
    .into();
    test_state_trie(state_trie, nibbles_64(0xADE), test_account_2())
}

#[test]
fn mpt_delete_branch_into_hash() -> Result<()> {
    let hash = Node::Hash(H256::random());
    let state_trie = Node::Extension {
        nibbles: nibbles_64(0xADF),
        child: hash.into(),
    }
    .into();
    test_state_trie(state_trie, nibbles_64(0xADE), test_account_2())
}

#[test]
fn test_after_mpt_delete_extension_branch() -> Result<()> {
    let hash = Node::Hash(H256::random());
    let branch = Node::Branch {
        children: std::array::from_fn(|i| {
            if i == 0 {
                Node::Empty.into()
            } else {
                hash.clone().into()
            }
        }),
        value: vec![],
    };
    let nibbles = Nibbles::from_bytes_be(&random::<[u8; 5]>()).unwrap();
    let state_trie = Node::Extension {
        nibbles,
        child: branch.into(),
    }
    .into();
    let key = nibbles.merge_nibbles(&Nibbles {
        packed: NibblesIntern::zero(),
        count: 64 - nibbles.count,
    });
    test_state_trie(state_trie, key, test_account_2())
}

/// Note: The account's storage_root is ignored, as we can't insert a new
/// storage_root without the accompanying trie data. An empty trie's
/// storage_root is used instead.
fn test_state_trie(
    state_trie: HashedPartialTrie,
    k: Nibbles,
    mut account: AccountRlp,
) -> Result<()> {
    assert_eq!(k.count, 64);

    // Ignore any storage_root; see documentation note.
    account.storage_root = HashedPartialTrie::from(Node::Empty).hash();

    let trie_inputs = TrieInputs {
        state_trie: state_trie.clone(),
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
        storage_tries: vec![],
    };
    let mpt_insert_state_trie = KERNEL.global_labels["mpt_insert_state_trie"];
    let mpt_delete = KERNEL.global_labels["mpt_delete"];
    let mpt_hash_state_trie = KERNEL.global_labels["mpt_hash_state_trie"];

    let initial_stack = vec![];
    let mut interpreter: Interpreter<F> = Interpreter::new(0, initial_stack, None);

    initialize_mpts(&mut interpreter, &trie_inputs);
    assert_eq!(interpreter.stack(), vec![]);

    // Set initial tries.
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push((Segment::StorageLinkedList as usize + 7).into())
        .expect("The stack should not overflow");
    interpreter
        .push((Segment::AccountsLinkedList as usize + 5).into())
        .expect("The stack should not overflow");
    interpreter.push(interpreter.get_global_metadata_field(GlobalMetadata::StateTrieRoot));

    // Now, set the payload.
    interpreter.generation_state.registers.program_counter =
        KERNEL.global_labels["mpt_set_payload"];

    interpreter.run()?;

    let acc_ptr = interpreter.pop().expect("The stack should not be empty") - 1;
    let storage_ptr = interpreter.pop().expect("The stack should not be empty") - 2;
    interpreter.set_global_metadata_field(GlobalMetadata::InitialAccountsLinkedListLen, acc_ptr);
    interpreter.set_global_metadata_field(GlobalMetadata::InitialStorageLinkedListLen, storage_ptr);

    // Next, execute mpt_insert_state_trie.
    interpreter.generation_state.registers.program_counter = mpt_insert_state_trie;
    let trie_data = interpreter.get_trie_data_mut();
    if trie_data.is_empty() {
        // In the assembly we skip over 0, knowing trie_data[0] = 0 by default.
        // Since we don't explicitly set it to 0, we need to do so here.
        trie_data.push(Some(0.into()));
    }
    let value_ptr = trie_data.len();
    trie_data.push(Some(account.nonce));
    trie_data.push(Some(account.balance));
    // In memory, storage_root gets interpreted as a pointer to a storage trie,
    // so we have to ensure the pointer is valid. It's easiest to set it to 0,
    // which works as an empty node, since trie_data[0] = 0 = MPT_TYPE_EMPTY.
    trie_data.push(Some(H256::zero().into_uint()));
    trie_data.push(Some(account.code_hash.into_uint()));
    let trie_data_len = trie_data.len().into();
    interpreter.set_global_metadata_field(GlobalMetadata::TrieDataSize, trie_data_len);
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(value_ptr.into())
        .expect("The stack should not overflow"); // value_ptr
    interpreter
        .push(k.try_into().unwrap())
        .expect("The stack should not overflow"); // key
    interpreter.run()?;
    assert_eq!(
        interpreter.stack().len(),
        0,
        "Expected empty stack after insert, found {:?}",
        interpreter.stack()
    );

    // Now, run `set_final_tries` so that the trie roots are correct.
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter.generation_state.registers.program_counter =
        KERNEL.global_labels["set_final_tries"];
    interpreter.run()?;

    // Next, execute mpt_delete, deleting the account we just inserted.
    let state_trie_ptr = interpreter.get_global_metadata_field(GlobalMetadata::StateTrieRoot);
    interpreter.generation_state.registers.program_counter = mpt_delete;
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(k.try_into().unwrap())
        .expect("The stack should not overflow");
    interpreter
        .push(64.into())
        .expect("The stack should not overflow");
    interpreter
        .push(state_trie_ptr)
        .expect("The stack should not overflow");
    interpreter.run()?;
    let state_trie_ptr = interpreter.pop().expect("The stack should not be empty");
    interpreter.set_global_metadata_field(GlobalMetadata::StateTrieRoot, state_trie_ptr);

    // Now, run `set_final_tries` again so that the trie roots are correct.
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter.generation_state.registers.program_counter =
        KERNEL.global_labels["set_final_tries"];
    interpreter.run()?;

    // Now, execute mpt_hash_state_trie.
    let expected_state_trie_hash = state_trie.hash();
    interpreter.set_global_metadata_field(
        GlobalMetadata::StateTrieRootDigestAfter,
        h2u(expected_state_trie_hash),
    );

    interpreter.generation_state.registers.program_counter = mpt_hash_state_trie;
    interpreter
        .halt_offsets
        .push(KERNEL.global_labels["check_txn_trie"]);
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(interpreter.get_global_metadata_field(GlobalMetadata::TrieDataSize)) // Initial trie data segment size, unused.
        .expect("The stack should not overflow");
    interpreter.run()?;

    assert_eq!(
        interpreter.stack().len(),
        2,
        "Expected 2 items on stack after hashing, found {:?}",
        interpreter.stack()
    );

    Ok(())
}
