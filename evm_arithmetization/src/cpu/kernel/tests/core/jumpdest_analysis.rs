use std::collections::{BTreeSet, HashMap};

use anyhow::Result;
use ethereum_types::U256;
use plonky2::field::goldilocks_field::GoldilocksField as F;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::opcodes::{get_opcode, get_push_opcode};
use crate::witness::operation::CONTEXT_SCALING_FACTOR;

#[test]
fn test_jumpdest_analysis() -> Result<()> {
    // By default the interpreter will skip jumpdest analysis asm and compute
    // the jumpdest table bits natively. We avoid that starting 1 line after
    // performing the missing first PROVER_INPUT "by hand"
    let jumpdest_analysis = KERNEL.global_labels["jumpdest_analysis"] + 1;
    const CONTEXT: usize = 3; // arbitrary

    let add = get_opcode("ADD");
    let push2 = get_push_opcode(2);
    let jumpdest = get_opcode("JUMPDEST");

    #[rustfmt::skip]
    let mut code: Vec<u8> = vec![
        add,
        jumpdest,
        push2,
        jumpdest, // part of PUSH2
        jumpdest, // part of PUSH2
        jumpdest,
        add,
        jumpdest,
    ];
    code.extend(
        (0..32)
            .rev()
            .map(get_push_opcode)
            .chain(std::iter::once(jumpdest)),
    );

    let mut jumpdest_bits = vec![false, true, false, false, false, true, false, true];
    // Add 32 falses and 1 true
    jumpdest_bits.extend(
        std::iter::repeat(false)
            .take(32)
            .chain(std::iter::once(true)),
    );

    let mut interpreter: Interpreter<F> = Interpreter::new(jumpdest_analysis, vec![], None);
    let code_len = code.len();

    interpreter.set_code(CONTEXT, code);
    interpreter.set_jumpdest_analysis_inputs(HashMap::from([(
        3,
        BTreeSet::from_iter(
            jumpdest_bits
                .iter()
                .enumerate()
                .filter(|&(_, &x)| x)
                .map(|(i, _)| i),
        ),
    )]));

    // The `set_jumpdest_analysis_inputs` method is never used.
    assert_eq!(
        interpreter.generation_state.jumpdest_table,
        // Context 3 has jumpdest 1, 5, 7. All have proof 0 and hence
        // the list [proof_0, jumpdest_0, ... ] is [0, 1, 0, 5, 0, 7, 8, 40]
        Some(HashMap::from([(3, vec![0, 1, 0, 5, 0, 7, 8, 40])]))
    );

    // Run jumpdest analysis with context = 3
    interpreter.generation_state.registers.context = CONTEXT;
    interpreter
        .push(0xDEADBEEFu32.into())
        .expect("The stack should not overflow");
    interpreter
        .push(code_len.into())
        .expect("The stack should not overflow");
    interpreter
        .push(U256::from(CONTEXT) << CONTEXT_SCALING_FACTOR)
        .expect("The stack should not overflow");

    // We need to manually pop the jumpdest_table and push its value on the top of
    // the stack
    interpreter
        .generation_state
        .jumpdest_table
        .as_mut()
        .unwrap()
        .get_mut(&CONTEXT)
        .unwrap()
        .pop();
    interpreter
        .push(41.into())
        .expect("The stack should not overflow");

    interpreter.run()?;
    assert_eq!(interpreter.stack(), vec![]);

    assert_eq!(jumpdest_bits, interpreter.get_jumpdest_bits(CONTEXT));

    Ok(())
}

#[test]
fn test_packed_verification() -> Result<()> {
    let write_table_if_jumpdest = KERNEL.global_labels["write_table_if_jumpdest"];
    const CONTEXT: usize = 3; // arbitrary

    let add = get_opcode("ADD");
    let jumpdest = get_opcode("JUMPDEST");

    let mut code: Vec<u8> = std::iter::once(add)
        .chain(
            (0..=31)
                .rev()
                .map(get_push_opcode)
                .chain(std::iter::once(jumpdest)),
        )
        .collect();

    let jumpdest_bits: Vec<bool> = std::iter::repeat(false)
        .take(33)
        .chain(std::iter::once(true))
        .collect();

    // Contract creation transaction.
    let initial_stack = vec![
        0xDEADBEEFu32.into(),
        U256::from(CONTEXT) << CONTEXT_SCALING_FACTOR,
        33.into(),
        U256::one(),
    ];
    let mut interpreter: Interpreter<F> =
        Interpreter::new(write_table_if_jumpdest, initial_stack.clone(), None);
    interpreter.set_code(CONTEXT, code.clone());
    interpreter.generation_state.jumpdest_table = Some(HashMap::from([(3, vec![1, 33])]));

    interpreter.run()?;

    assert_eq!(jumpdest_bits, interpreter.get_jumpdest_bits(CONTEXT));

    // If we add 1 to each opcode the jumpdest at position 32 is never a valid
    // jumpdest
    for i in 1..=32 {
        code[i] += 1;
        let mut interpreter: Interpreter<F> =
            Interpreter::new(write_table_if_jumpdest, initial_stack.clone(), None);
        interpreter.set_code(CONTEXT, code.clone());
        interpreter.generation_state.jumpdest_table = Some(HashMap::from([(3, vec![1, 33])]));

        assert!(interpreter.run().is_err());

        assert!(interpreter.get_jumpdest_bits(CONTEXT).is_empty());

        code[i] -= 1;
    }

    Ok(())
}

#[test]
fn test_verify_non_jumpdest() -> Result<()> {
    // By default the interpreter will skip jumpdest analysis asm and compute
    // the jumpdest table bits natively. We avoid that starting 1 line after
    // performing the missing first PROVER_INPUT "by hand"
    let verify_non_jumpdest = KERNEL.global_labels["verify_non_jumpdest"];
    const CONTEXT: usize = 3; // arbitrary

    let add = get_opcode("ADD");
    let push2 = get_push_opcode(2);
    let jumpdest = get_opcode("JUMPDEST");

    #[rustfmt::skip]
    let mut code: Vec<u8> = vec![
        add,
        jumpdest,
        push2,
        jumpdest, // part of PUSH2
        jumpdest, // part of PUSH2
        jumpdest,
        add,
        jumpdest,
    ];
    code.extend(
        (0..32)
            .rev()
            .map(get_push_opcode)
            .chain(std::iter::once(jumpdest)),
    );
    let code_len = code.len();

    // If we add 1 to each opcode the jumpdest at position 32 is never a valid
    // jumpdest
    for i in 8..code_len - 1 {
        code[i] += 1;
        let mut interpreter: Interpreter<F> = Interpreter::new(verify_non_jumpdest, vec![], None);
        interpreter.generation_state.registers.context = CONTEXT;

        interpreter.set_code(CONTEXT, code.clone());
        code[i] -= 1;

        // We check that all non jumpdests are indeed non jumpdests
        for j in (0..code.len()).filter(|&i| i != 1 && i != 5 && i != 7) {
            interpreter.generation_state.registers.program_counter = verify_non_jumpdest;
            interpreter
                .push(0xDEADBEEFu32.into())
                .expect("The stack should not overflow");
            interpreter
                .push(j.into())
                .expect("The stack should not overflow");
            interpreter.run()?;
            assert!(interpreter.stack().is_empty());
            assert_eq!(interpreter.get_jumpdest_bit(j), U256::zero());
        }
    }
    Ok(())
}
