use std::collections::HashSet;

use anyhow::Result;
use env_logger::try_init_from_env;
use env_logger::Env;
use env_logger::DEFAULT_FILTER_ENV;
use ethereum_types::{Address, H160, U256};
use itertools::Itertools;
use num::traits::ToBytes;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2_maybe_rayon::rayon::iter;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment::{self, AccessedAddresses, AccessedStorageKeys};
use crate::witness::memory::MemoryAddress;

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}

#[test]
fn test_init_linked_lists() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_accounts_linked_list"];

    // Check the initial state of the linked list in the kernel.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    assert!(interpreter.stack().is_empty());

    let acc_addr_list: Vec<U256> = (0..4)
        .map(|i| {
            interpreter
                .generation_state
                .memory
                .get_with_init(MemoryAddress::new(0, Segment::AccountsLinkedList, i))
        })
        .collect();
    assert_eq!(
        vec![
            U256::MAX,
            U256::zero(),
            U256::zero(),
            (Segment::AccountsLinkedList as usize).into(),
        ],
        acc_addr_list
    );

    Ok(())
}

#[test]
fn test_list_iterator() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_accounts_linked_list"];

    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    // test the list iterator
    let mut list = interpreter
        .generation_state
        .get_accounts_linked_list()
        .expect("Since we called init_access_lists there must be a list");

    let Some((pos_0, addr, ptr, ctr)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(pos_0, 0);
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    let Some((pos_0, addr, ptr, ctr)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(pos_0, 0);
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    Ok(())
}

#[test]
fn test_insert_account() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_accounts_linked_list"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_account_label = KERNEL.global_labels["insert_account"];

    let retaddr = 0xdeadbeefu32.into();
    let mut rng = thread_rng();
    let address: H160 = rng.gen();
    let payload_ptr = U256::from(5);

    assert!(address != H160::zero(), "Cosmic luck or bad RNG?");

    interpreter.push(retaddr);
    interpreter.push(payload_ptr);
    interpreter.push(U256::from(address.0.as_slice()));
    interpreter.generation_state.registers.program_counter = insert_account_label;

    interpreter.run()?;
    assert_eq!(interpreter.stack(), &[payload_ptr, U256::zero()]);

    let mut list = interpreter
        .generation_state
        .get_accounts_linked_list()
        .expect("Since we called init_access_lists there must be a list");

    let Some((old_pos, addr, ptr, ctr)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(old_pos, 0);
    assert_eq!(addr, U256::from(address.0.as_slice()));
    assert_eq!(ptr, payload_ptr);
    assert_eq!(ctr, U256::zero());
    let Some((old_pos, addr, ptr, ctr)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(old_pos, 4);
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());

    Ok(())
}

#[test]
fn test_insert_and_delete_accounts() -> Result<()> {
    init_logger();

    let init_label = KERNEL.global_labels["init_accounts_linked_list"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_account_label = KERNEL.global_labels["insert_account"];

    let retaddr = 0xdeadbeefu32.into();
    let mut rng = thread_rng();
    let n = 10;
    let mut addresses = (0..n)
        // .map(|_| rng.gen::<Address>())
        .map(|i| Address::from_low_u64_be(i as u64 + 5))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<Address>>();
    let delta_ptr = 100;
    // let addr_not_in_list = rng.gen::<Address>();
    let addr_not_in_list = Address::from_low_u64_be(4);
    assert!(
        !addresses.contains(&addr_not_in_list),
        "Cosmic luck or bad RNG?"
    );

    let offset = Segment::AccountsLinkedList as usize;
    // Insert all addresses
    for i in 0..n {
        let addr = U256::from(addresses[i as usize].0.as_slice());
        interpreter.push(0xdeadbeefu32.into());
        interpreter.push(addr + delta_ptr); // ptr = addr + delta_ptr for the sake of the test
        interpreter.push(addr);
        interpreter.generation_state.registers.program_counter = insert_account_label;
        interpreter.run()?;
        assert_eq!(
            interpreter.pop().expect("The stack can't be empty"),
            U256::zero()
        );
        assert_eq!(
            interpreter.pop().expect("The stack can't be empty"),
            addr + delta_ptr
        );
        // The counter must be 0
        assert_eq!(
            interpreter.generation_state.memory.get_with_init(
                MemoryAddress::new_bundle(U256::from(offset + 4 * (i + 1) + 2)).unwrap(),
            ),
            U256::zero()
        );
    }

    // The next free address in Segment::AccounLinkedList must be offset + (n +
    // 1)*4.
    assert_eq!(
        interpreter.generation_state.memory.get_with_init(
            MemoryAddress::new_bundle(U256::from(GlobalMetadata::AccountsLinkedListLen as usize))
                .unwrap(),
        ),
        U256::from(offset + (n + 1) * 4)
    );

    // Test for address already in list.
    for i in 0..n {
        let addr_in_list = U256::from(addresses[i as usize].0.as_slice());
        interpreter.push(retaddr);
        interpreter.push(U256::zero());
        interpreter.push(addr_in_list);
        interpreter.generation_state.registers.program_counter = insert_account_label;
        interpreter.run()?;
        assert_eq!(
            interpreter.pop().expect("The stack can't be empty"),
            U256::one()
        );
        assert_eq!(
            interpreter.pop().expect("The stack can't be empty"),
            addr_in_list + delta_ptr
        );
        // The counter must be one now
        assert_eq!(
            interpreter.generation_state.memory.get_with_init(
                MemoryAddress::new_bundle(U256::from(offset + 4 * (i + 1) + 2)).unwrap(),
            ),
            U256::one()
        );
    }

    // Test for address not in the list.
    interpreter.push(retaddr);
    interpreter.push(U256::from(addr_not_in_list.0.as_slice()) + delta_ptr);
    interpreter.push(U256::from(addr_not_in_list.0.as_slice()));
    interpreter.generation_state.registers.program_counter = insert_account_label;

    interpreter.run()?;
    assert_eq!(
        interpreter.pop().expect("The stack can't be empty"),
        U256::zero()
    );
    assert_eq!(
        interpreter.pop().expect("The stack can't be empty"),
        U256::from(addr_not_in_list.0.as_slice()) + delta_ptr
    );

    // Now the list of accounts have address 4
    addresses.push(addr_not_in_list);

    // The next free address in Segment::AccounLinkedList must be offset + (n +
    // 2)*4.
    assert_eq!(
        interpreter.generation_state.memory.get_with_init(
            MemoryAddress::new_bundle(U256::from(GlobalMetadata::AccountsLinkedListLen as usize))
                .unwrap(),
        ),
        U256::from(offset + (n + 2) * 4)
    );

    // Remove all even nodes
    let delete_account_label = KERNEL.global_labels["remove_account"];

    let mut new_addresses = vec![];

    for (i, j) in (0..n).tuples() {
        // Test for address already in list.
        let addr_in_list = U256::from(addresses[i as usize].0.as_slice());
        interpreter.push(retaddr);
        interpreter.push(addr_in_list);
        interpreter.generation_state.registers.program_counter = delete_account_label;
        interpreter.run()?;
        assert!(interpreter.stack().is_empty());
        // we add the non deleted addres to new_addresses
        new_addresses.push(addresses[j]);
    }
    // the last address is not removed
    new_addresses.push(*addresses.last().unwrap());

    // We need to sort the list in order to properly compare with
    // the linked list the interpreter's memory
    new_addresses.sort();

    let mut list = interpreter
        .generation_state
        .get_accounts_linked_list()
        .expect("Since we called init_access_lists there must be a list");

    for (i, (_, addr, ptr, ctr)) in list.enumerate() {
        if addr == U256::MAX {
            //
            assert_eq!(addr, U256::MAX);
            assert_eq!(ptr, U256::zero());
            assert_eq!(ctr, U256::zero());
            break;
        }
        let addr_in_list = U256::from(new_addresses[i].0.as_slice());
        assert_eq!(addr, addr_in_list);
        assert_eq!(ptr, addr + delta_ptr);
        // ctr is 0 for the lowest address because is never accessed
        assert_eq!(ctr, if i == 0 { U256::zero() } else { U256::one() });
    }

    Ok(())
}
