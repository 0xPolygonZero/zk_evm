use anyhow::Result;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::prepare_interpreter;
use crate::generation::mpt::AccountRlp;
use crate::testing_utils::init_logger;
use crate::Node;

// Test account with a given code hash.
fn test_account(balance: U256) -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance,
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: H256::from_uint(&U256::from(8888)),
    }
}

#[test]
fn test_balance() -> Result<()> {
    init_logger();
    let mut rng = thread_rng();
    let balance = U256(rng.gen());
    let account = test_account(balance);

    let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![], None);
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
