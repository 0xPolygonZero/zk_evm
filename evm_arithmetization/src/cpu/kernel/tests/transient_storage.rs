use anyhow::Result;
use ethereum_types::U256;
use once_cell::sync::Lazy;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2::field::types::Field;

use crate::cpu::kernel::aggregator::{
    combined_kernel_from_files, KERNEL_FILES, NUMBER_KERNEL_FILES,
};
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::generation::state::GenerationState;
use crate::memory::segments::Segment;
use crate::witness::memory::MemoryAddress;
use crate::GenerationInputs;

fn initialize_interpreter<F: Field>(interpreter: &mut Interpreter<F>, gas_limit: U256) {
    let gas_limit_address = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::GasLimit.unscale(),
    };
    interpreter
        .generation_state
        .memory
        .set(gas_limit_address, gas_limit);

    let addr_addr = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::Address.unscale(),
    };
    interpreter.generation_state.memory.set(addr_addr, 3.into());

    let initial_len = MemoryAddress {
        context: 0,
        segment: Segment::GlobalMetadata.unscale(),
        virt: GlobalMetadata::TransientStorageLen.unscale(),
    };
    // Store 0 but scaled by its segment
    interpreter
        .generation_state
        .memory
        .set(initial_len, (Segment::TransientStorage as usize).into());
}

#[test]
fn test_tstore() -> Result<()> {
    let sys_tstore = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_tstore"];

    let kexit_info = U256::from(0xdeadbeefu32) + (U256::from(u64::from(true)) << 32);

    let initial_stack = vec![
        1.into(), // val
        2.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new(sys_tstore, initial_stack, None);
    initialize_interpreter(&mut interpreter, 100.into());

    interpreter.run()?;

    assert_eq!(interpreter.generation_state.registers.gas_used, 100);

    let stored_addr = MemoryAddress::new(0, Segment::TransientStorage, 0);
    let stored_slot = MemoryAddress::new(0, Segment::TransientStorage, 1);
    let stored_val = MemoryAddress::new(0, Segment::TransientStorage, 2);
    assert_eq!(
        interpreter
            .generation_state
            .memory
            .get(stored_addr)
            .unwrap(),
        3.into(),
    );
    assert_eq!(
        interpreter
            .generation_state
            .memory
            .get(stored_slot)
            .unwrap(),
        2.into(),
    );
    assert_eq!(
        interpreter.generation_state.memory.get(stored_val).unwrap(),
        1.into(),
    );

    Ok(())
}

#[test]
fn test_tstore_tload() -> Result<()> {
    let sys_tstore = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_tstore"];

    let kexit_info = U256::from(0xdeadbeefu32) + (U256::from(u64::from(true)) << 32);

    let initial_stack = vec![
        1.into(), // val
        2.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new(sys_tstore, initial_stack, None);
    initialize_interpreter(&mut interpreter, 200.into());

    interpreter.run()?;

    assert_eq!(interpreter.generation_state.registers.gas_used, 100);

    let sys_tload = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_tload"];
    let kexit_info = U256::from(0xdeadbeefu32)
        + (U256::from(u64::from(true)) << 32)
        + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter
        .push(2.into())
        .expect("The stack should not overflow");
    interpreter
        .push(kexit_info)
        .expect("The stack should not overflow");

    interpreter.run()?;

    assert_eq!(interpreter.generation_state.registers.gas_used, 200);

    let val = interpreter.pop().unwrap();

    assert_eq!(val, 1.into());

    // Load non-existing slot
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.is_kernel = true;
    let slot: U256 = 4.into();
    interpreter
        .push(slot)
        .expect("The stack should not overflow");
    interpreter
        .push(kexit_info)
        .expect("The stack should not overflow");

    interpreter.run()?;

    let val = interpreter.stack()[0];

    assert_eq!(U256::zero(), val);
    Ok(())
}

#[test]
fn test_many_tstore_many_tload() -> Result<()> {
    let kexit_info = U256::from(0xdeadbeefu32) + (U256::from(u64::from(true)) << 32);
    let sys_tstore = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_tstore"];

    let initial_stack = vec![
        1.into(), // val
        2.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new(0, initial_stack, None);
    initialize_interpreter(&mut interpreter, (10 * 200).into());

    for i in 0..10 {
        interpreter.generation_state.registers.program_counter = sys_tstore;
        interpreter.generation_state.registers.is_kernel = true;
        let kexit_info = U256::from(0xdeadbeefu32)
            + (U256::from(u64::from(true)) << 32)
            + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
        let val: U256 = i.into();
        let slot: U256 = i.into();
        interpreter
            .push(val)
            .expect("The stack should not overflow");
        interpreter
            .push(slot)
            .expect("The stack should not overflow");
        interpreter
            .push(kexit_info)
            .expect("The stack should not overflow");

        interpreter.run()?;
        assert_eq!(
            interpreter.generation_state.registers.gas_used,
            100 * (i + 1)
        );
    }

    let sys_tload = crate::cpu::kernel::aggregator::KERNEL.global_labels["sys_tload"];

    for i in 0..10 {
        interpreter.generation_state.registers.program_counter = sys_tload;
        interpreter.generation_state.registers.is_kernel = true;
        let kexit_info = U256::from(0xdeadbeefu32)
            + (U256::from(u64::from(true)) << 32)
            + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
        let slot: U256 = i.into();
        interpreter
            .push(slot)
            .expect("The stack should not overflow");
        interpreter
            .push(kexit_info)
            .expect("The stack should not overflow");

        interpreter.run()?;
        assert_eq!(
            interpreter.generation_state.registers.gas_used,
            100 * (i + 10 + 1)
        );

        assert_eq!(U256::from(i), interpreter.pop().unwrap());
    }

    Ok(())
}

#[test]
fn test_revert() -> Result<()> {
    // We use a modified kernel with an extra file defining a label
    // where the `checkpoint` macro from file cpu/kernel/asm/journal/journal.asm
    // is expanded.
    const NUMBER_FILES: usize = NUMBER_KERNEL_FILES + 1;
    static KERNEL: Lazy<Kernel> = Lazy::new(|| {
        combined_kernel_from_files(std::array::from_fn::<_, NUMBER_FILES, _>(|i| {
            if i < NUMBER_KERNEL_FILES {
                KERNEL_FILES[i]
            } else {
                include_str!("checkpoint_label.asm")
            }
        }))
    });

    let sys_tstore = KERNEL.global_labels["sys_tstore"];
    let mut interpreter = Interpreter::<F>::new(sys_tstore, vec![], None);
    interpreter.generation_state =
        GenerationState::<F>::new(&GenerationInputs::default(), &KERNEL.code).unwrap();
    initialize_interpreter(&mut interpreter, (20 * 100).into());

    // Store different values at slot 1
    for i in 0..10 {
        interpreter.generation_state.registers.program_counter = sys_tstore;
        interpreter.generation_state.registers.is_kernel = true;
        let kexit_info = U256::from(0xdeadbeefu32)
            + (U256::from(u64::from(true)) << 32)
            + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
        let val: U256 = i.into();
        let slot: U256 = 1.into();
        interpreter
            .push(val)
            .expect("The stack should not overflow");
        interpreter
            .push(slot)
            .expect("The stack should not overflow");
        interpreter
            .push(kexit_info)
            .expect("The stack should not overflow");

        interpreter.run()?;
        assert_eq!(
            interpreter.generation_state.registers.gas_used,
            100 * (i + 1)
        );
    }

    let gas_before_checkpoint = interpreter.generation_state.registers.gas_used;

    // We will revert to the point where `val` was 9
    let checkpoint = KERNEL.global_labels["checkpoint"];
    interpreter.generation_state.registers.program_counter = checkpoint;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter
        .push(0xdeadbeefu32.into())
        .expect("The stack should not overflow");
    interpreter.run()?;
    assert!(interpreter.stack().is_empty());

    // Don't charge gas for the checkpoint
    interpreter.generation_state.registers.gas_used = gas_before_checkpoint;

    // Now we change `val` 10 more times
    for i in 10..20 {
        interpreter.generation_state.registers.program_counter = sys_tstore;
        interpreter.generation_state.registers.is_kernel = true;
        let kexit_info = U256::from(0xdeadbeefu32)
            + (U256::from(u64::from(true)) << 32)
            + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
        let val: U256 = i.into();
        let slot: U256 = 1.into();
        interpreter
            .push(val)
            .expect("The stack should not overflow");
        interpreter
            .push(slot)
            .expect("The stack should not overflow");
        interpreter
            .push(kexit_info)
            .expect("The stack should not overflow");

        interpreter.run()?;
        assert_eq!(
            interpreter.generation_state.registers.gas_used,
            100 * (i + 1)
        );
    }

    // The interpreter will run out of gas and revert to the checkpoint
    interpreter.generation_state.registers.program_counter = sys_tstore;
    interpreter.generation_state.registers.is_kernel = true;
    let kexit_info = U256::from(0xdeadbeefu32)
        + (U256::from(u64::from(true)) << 32)
        + (U256::from(interpreter.generation_state.registers.gas_used) << 192);
    interpreter
        .push(3.into())
        .expect("The stack should not overflow"); // val
    interpreter
        .push(2.into())
        .expect("The stack should not overflow"); // slot
    interpreter
        .push(kexit_info)
        .expect("The stack should not overflow");
    assert!(interpreter.run().is_err());

    // Now we should load the value before the revert
    let sys_tload = KERNEL.global_labels["sys_tload"];
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.gas_used = 0;
    let kexit_info = U256::from(0xdeadbeefu32) + (U256::from(u64::from(true)) << 32);
    interpreter.generation_state.registers.is_kernel = true;
    interpreter
        .push(1.into())
        .expect("The stack should not overflow");
    interpreter
        .push(kexit_info)
        .expect("The stack should not overflow");

    interpreter.run()?;

    assert_eq!(interpreter.pop().unwrap(), 9.into());

    Ok(())
}
