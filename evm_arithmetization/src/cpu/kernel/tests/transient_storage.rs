use std::array;

use anyhow::Result;
use ethereum_types::{Address, U256};
use pest::error::Error;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::{combined_kernel_from_files, KERNEL, KERNEL_FILES};
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryAddress;

#[test]
fn test_tstore() -> Result<()> {
    let sys_tstore = KERNEL.global_labels["sys_tstore"];

    let kexit_info = 0xdeadbeefu32.into();

    let initial_stack = vec![
        0xD0D0CACAu32.into(), // val
        0xF0CACC1Au32.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new_with_kernel(sys_tstore, initial_stack);
    let gas_limit_address = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::GasLimit.unscale(),
    };
    let addr_addr = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::Address.unscale(),
    };

    interpreter
        .generation_state
        .memory
        .set(gas_limit_address, 100.into());
    interpreter
        .generation_state
        .memory
        .set(addr_addr, 0xCACABEBEu32.into());

    interpreter.run()?;

    let stored_addr = MemoryAddress::new(0, Segment::TransientStorage, 0);
    let stored_slot = MemoryAddress::new(0, Segment::TransientStorage, 1);
    let stored_val = MemoryAddress::new(0, Segment::TransientStorage, 2);
    assert_eq!(
        interpreter.generation_state.memory.get(stored_addr),
        0xCACABEBEu32.into(),
    );
    assert_eq!(
        interpreter.generation_state.memory.get(stored_slot),
        0xF0CACC1Au32.into(),
    );
    assert_eq!(
        interpreter.generation_state.memory.get(stored_val),
        0xD0D0CACAu32.into(),
    );

    Ok(())
}

#[test]
fn test_tstore_tload() -> Result<()> {
    let sys_tstore = KERNEL.global_labels["sys_tstore"];

    let kexit_info = 0xdeadbeefu32.into();

    let initial_stack = vec![
        1.into(), // val
        2.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new_with_kernel(sys_tstore, initial_stack);
    let gas_limit_address = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::GasLimit.unscale(),
    };
    let addr_addr = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::Address.unscale(),
    };

    interpreter
        .generation_state
        .memory
        .set(gas_limit_address, 200.into());
    interpreter.generation_state.memory.set(addr_addr, 3.into());

    interpreter.run()?;

    let sys_tload = KERNEL.global_labels["sys_tload"];
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.push(2.into());
    interpreter.push(kexit_info);

    interpreter.run()?;

    let val = interpreter.pop().unwrap();

    assert_eq!(val, 1.into());

    // Load non-existing slot
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.is_kernel = true;
    let slot: U256 = 4.into();
    interpreter.push(slot);
    interpreter.push(kexit_info);

    interpreter.run()?;

    println!("{:?}", interpreter.stack());
    let val = interpreter.stack()[0];

    assert_eq!(U256::zero(), val);
    Ok(())
}

#[test]
fn test_many_tstore_many_tload() -> Result<()> {
    let kexit_info = 0xdeadbeefu32.into();

    let initial_stack = vec![
        1.into(), // val
        2.into(), // slot
        kexit_info,
    ];

    let mut interpreter: Interpreter<F> = Interpreter::new_with_kernel(0, initial_stack);
    let gas_limit_address = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::GasLimit.unscale(),
    };
    let addr_addr = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::Address.unscale(),
    };

    interpreter
        .generation_state
        .memory
        .set(gas_limit_address, (200 * 200).into());
    interpreter.generation_state.memory.set(addr_addr, 3.into());

    let sys_tstore = KERNEL.global_labels["sys_tstore"];

    for i in (0..100) {
        interpreter.generation_state.registers.program_counter = sys_tstore;
        interpreter.generation_state.registers.is_kernel = true;
        let val: U256 = i.into();
        let slot: U256 = i.into();
        interpreter.push(val);
        interpreter.push(slot);
        interpreter.push(kexit_info);

        interpreter.run()?;
        println!("Store {i}");
    }

    let sys_tload = KERNEL.global_labels["sys_tload"];

    for i in (0..100) {
        interpreter.generation_state.registers.program_counter = sys_tload;
        interpreter.generation_state.registers.is_kernel = true;
        let slot: U256 = i.into();
        interpreter.push(slot);
        interpreter.push(kexit_info);

        interpreter.run()?;

        let val = interpreter.pop().unwrap();

        println!("Load {i}");
        assert_eq!(U256::from(i), val);
    }

    Ok(())
}

#[test]
fn test_revert() -> Result<()> {
    let kernel_files: [&str; 150] = array::from_fn(|i| {
        if i < KERNEL_FILES.len() {
            KERNEL_FILES[i]
        } else {
            include_str!("transient_storage.asm")
        }
    });
    let kernel = combined_kernel_from_files(kernel_files);

    let sys_tstore = kernel.global_labels["sys_tstore"];

    let mut interpreter: Interpreter<F> =
        Interpreter::new(&kernel.code, sys_tstore, vec![], &kernel.prover_inputs);

    let gas_limit_address = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::GasLimit.unscale(),
    };
    let addr_addr = MemoryAddress {
        context: 0,
        segment: Segment::ContextMetadata.unscale(),
        virt: ContextMetadata::Address.unscale(),
    };

    interpreter
        .generation_state
        .memory
        .set(gas_limit_address, 200.into());
    interpreter.generation_state.memory.set(addr_addr, 3.into());

    // Store 1 at 2
    let kexit_info = 0xdeadbeefu32.into();

    interpreter.push(1.into()); // val
    interpreter.push(2.into()); // slot
    interpreter.push(kexit_info);
    interpreter.run()?;

    println!("Santa chachucha!");

    // We will revert to this point
    let checkpoint = kernel.global_labels["checkpoint"];
    println!("checkpoint = {checkpoint}");
    interpreter.generation_state.registers.program_counter = checkpoint;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.run()?;

    // Store 2 at 2
    interpreter.generation_state.registers.program_counter = sys_tstore;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.push(2.into()); // val
    interpreter.push(2.into()); // slot
    interpreter.push(kexit_info);
    interpreter.run()?;

    // We will run out of gas
    interpreter.generation_state.registers.program_counter = sys_tstore;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.push(2.into()); // val
    interpreter.push(2.into()); // slot
    interpreter.push(kexit_info);
    assert!(interpreter.run().is_err());

    // Now we should load the value before the revert
    let sys_tload = kernel.global_labels["sys_tload"];
    interpreter.generation_state.registers.program_counter = sys_tload;
    interpreter.generation_state.registers.is_kernel = true;
    interpreter.push(2.into());
    interpreter.push(kexit_info);

    interpreter.run()?;

    let val = interpreter.pop().unwrap();

    assert_eq!(val, 1.into());

    Ok(())
}
