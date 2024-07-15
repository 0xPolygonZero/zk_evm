use anyhow::Result;
use ethereum_types::{H160, U256};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::{thread_rng, Rng};
use smt_trie::db::MemoryDb;
use smt_trie::keys::key_balance;
use smt_trie::smt::Smt;
use smt_trie::utils::key2u;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::initialize_mpts;
use crate::generation::TrieInputs;

#[test]
fn smt_read() -> Result<()> {
    let mut state_smt = Smt::<MemoryDb>::default();
    let key = key_balance(H160(thread_rng().gen()));
    let value = U256(thread_rng().gen());
    state_smt.set(key, value);
    let trie_inputs = TrieInputs {
        state_smt: state_smt.serialize(),
        transactions_trie: Default::default(),
        receipts_trie: Default::default(),
    };

    let smt_read_state = KERNEL.global_labels["smt_read_state"];

    let initial_stack = vec![];
    let mut interpreter: Interpreter<F> = Interpreter::new(0, initial_stack);
    initialize_mpts(&mut interpreter, &trie_inputs);
    assert_eq!(interpreter.stack(), vec![]);

    // Now, execute mpt_read on the state trie.
    interpreter.generation_state.registers.program_counter = smt_read_state;
    interpreter
        .push(0xdeadbeefu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(key2u(key))
        .expect("The stack should not overflow");
    interpreter.run()?;

    assert_eq!(interpreter.stack().len(), 1);
    let result_ptr = interpreter.stack()[0].as_usize();
    let result = interpreter.get_trie_data()[result_ptr];
    assert_eq!(result, value);

    Ok(())
}
