use std::collections::HashMap;

use anyhow::Result;
use ethereum_types::{Address, U256};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::hash::hash_types::RichField;
use rand::{thread_rng, Rng};
use smt_trie::db::MemoryDb;
use smt_trie::keys::{key_balance, key_code, key_code_length, key_nonce};
use smt_trie::smt::Smt;
use smt_trie::utils::{hashout2u, key2u};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::{initialize_mpts, set_account};
use crate::generation::mpt::AccountRlp;

// Test account with a given code hash.
fn test_account(balance: U256) -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance,
        code_hash: U256::from(8888),
        code_length: 42.into(), // arbitrary
    }
}

// Stolen from `tests/mpt/insert.rs`
// Prepare the interpreter by inserting the account in the state trie.
fn prepare_interpreter<F: RichField>(
    interpreter: &mut Interpreter<F>,
    address: Address,
    account: &AccountRlp,
) -> Result<()> {
    let smt_insert_state = KERNEL.global_labels["smt_insert_state"];
    let smt_hash_state = KERNEL.global_labels["smt_hash_state"];
    let mut state_smt = Smt::<MemoryDb>::default();
    let trie_inputs = Default::default();

    initialize_mpts(interpreter, &trie_inputs);
    assert_eq!(interpreter.stack(), vec![]);

    // Next, execute smt_insert_state.
    interpreter.generation_state.registers.program_counter = smt_insert_state;
    let trie_data = interpreter.get_trie_data_mut();
    if trie_data.is_empty() {
        // In the assembly we skip over 0, knowing trie_data[0] = 0 by default.
        // Since we don't explicitly set it to 0, we need to do so here.
        trie_data.push(Some(0.into()));
        trie_data.push(Some(0.into()));
    }
    let trie_data_len = trie_data.len().into();
    interpreter.set_global_metadata_field(GlobalMetadata::TrieDataSize, trie_data_len);
    for (key, value) in [
        (key_balance(address), account.balance),
        (key_nonce(address), account.nonce),
        (key_code(address), account.code_hash),
        (key_code_length(address), account.code_length),
    ] {
        if value.is_zero() {
            continue;
        }
        interpreter.generation_state.registers.program_counter = smt_insert_state;
        interpreter
            .push(0xDEADBEEFu32.into())
            .expect("The stack should not overflow");
        interpreter
            .push(value)
            .expect("The stack should not overflow"); // value_ptr
        let keyu = key2u(key);
        interpreter
            .push(keyu)
            .expect("The stack should not overflow"); // key

        interpreter.run()?;
        assert_eq!(
            interpreter.stack().len(),
            0,
            "Expected empty stack after insert, found {:?}",
            interpreter.stack()
        );
    }

    interpreter.run()?;
    assert_eq!(
        interpreter.stack().len(),
        0,
        "Expected empty stack after insert, found {:?}",
        interpreter.stack()
    );

    // Now, execute smt_hash_state.
    interpreter.generation_state.registers.program_counter = smt_hash_state;
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(2.into()) // Initial trie data segment size, unused.
        .expect("The stack should not overflow");
    interpreter.run()?;

    assert_eq!(
        interpreter.stack().len(),
        2,
        "Expected 2 items on stack after hashing, found {:?}",
        interpreter.stack()
    );
    let hash = interpreter.stack()[1];

    set_account(&mut state_smt, address, account, &HashMap::new());
    let expected_state_trie_hash = hashout2u(state_smt.root);
    assert_eq!(hash, expected_state_trie_hash);

    Ok(())
}

#[test]
fn test_balance() -> Result<()> {
    let mut rng = thread_rng();
    let balance = U256(rng.gen());
    let account = test_account(balance);

    let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![]);
    let address: Address = rng.gen();
    // Prepare the interpreter by inserting the account in the state trie.
    prepare_interpreter(&mut interpreter, address, &account)?;

    // Test `balance`
    interpreter.generation_state.registers.program_counter = KERNEL.global_labels["balance"];
    interpreter.pop().expect("The stack should not be empty");
    interpreter.pop().expect("The stack should not be empty");
    assert!(interpreter.stack().is_empty());
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(U256::from_big_endian(address.as_bytes()))
        .expect("The stack should not overflow");
    interpreter.run()?;

    assert_eq!(interpreter.stack(), vec![balance]);

    Ok(())
}
