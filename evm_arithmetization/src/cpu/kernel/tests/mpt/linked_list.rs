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
use crate::util::u256_to_usize;
use crate::witness::errors::ProgramError;
use crate::witness::errors::ProverInputError::InvalidInput;
use crate::witness::memory::MemoryAddress;

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}

#[test]
fn test_init_linked_lists() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_linked_lists"];

    // Check the initial state of the linked list in the kernel.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    assert!(interpreter.stack().is_empty());

    // Check the initial accounts linked list
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

    // Check the inital storage linked list
    let acc_addr_list: Vec<U256> = (0..5)
        .map(|i| {
            interpreter
                .generation_state
                .memory
                .get_with_init(MemoryAddress::new(0, Segment::StorageLinkedList, i))
        })
        .collect();
    assert_eq!(
        vec![
            U256::MAX,
            U256::zero(),
            U256::zero(),
            U256::zero(),
            (Segment::StorageLinkedList as usize).into(),
        ],
        acc_addr_list
    );

    Ok(())
}

#[test]
fn test_list_iterator() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_linked_lists"];

    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    // test the list iterator
    let mut accounts_list = interpreter
        .generation_state
        .get_accounts_linked_list()
        .expect("Since we called init_access_lists there must be an accounts list");

    let Some([addr, ptr, ctr, scaled_pos_1]) = accounts_list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(scaled_pos_1, (Segment::AccountsLinkedList as usize).into());
    let Some([addr, ptr, ctr, scaled_pos_1]) = accounts_list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(scaled_pos_1, (Segment::AccountsLinkedList as usize).into());

    let mut storage_list = interpreter
        .generation_state
        .get_storage_linked_list()
        .expect("Since we called init_access_lists there must be a storage list");
    let Some([addr, key, ptr, ctr, scaled_pos_1]) = storage_list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::MAX);
    assert_eq!(key, U256::zero());
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(scaled_pos_1, (Segment::StorageLinkedList as usize).into());
    let Some([addr, key, ptr, ctr, scaled_pos_1]) = storage_list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(scaled_pos_1, (Segment::StorageLinkedList as usize).into());

    Ok(())
}

#[test]
fn test_insert_account() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_linked_lists"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_account_label = KERNEL.global_labels["insert_account_to_linked_list"];

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

    let Some([addr, ptr, ctr, scaled_next_pos]) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::from(address.0.as_slice()));
    assert_eq!(ptr, payload_ptr);
    assert_eq!(ctr, U256::zero());
    assert_eq!(
        scaled_next_pos,
        (Segment::AccountsLinkedList as usize).into()
    );
    let Some([addr, ptr, ctr, scaled_new_pos]) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(addr, U256::MAX);
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(
        scaled_new_pos,
        (Segment::AccountsLinkedList as usize + 4).into()
    );
    Ok(())
}

#[test]
fn test_insert_storage() -> Result<()> {
    init_logger();
    let init_label = KERNEL.global_labels["init_linked_lists"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_account_label = KERNEL.global_labels["insert_slot"];

    let retaddr = 0xdeadbeefu32.into();
    let mut rng = thread_rng();
    let address: H160 = rng.gen();
    let key: H160 = rng.gen();
    let payload_ptr = U256::from(5);

    assert!(address != H160::zero(), "Cosmic luck or bad RNG?");

    interpreter.push(retaddr);
    interpreter.push(payload_ptr);
    interpreter.push(U256::from(key.0.as_slice()));
    interpreter.push(U256::from(address.0.as_slice()));
    interpreter.generation_state.registers.program_counter = insert_account_label;

    interpreter.run()?;
    assert_eq!(interpreter.stack(), &[payload_ptr, U256::zero()]);

    let mut list = interpreter
        .generation_state
        .get_storage_linked_list()
        .expect("Since we called init_access_lists there must be a list");

    let Some([inserted_addr, inserted_key, ptr, ctr, scaled_next_pos]) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(inserted_addr, U256::from(address.0.as_slice()));
    assert_eq!(inserted_key, U256::from(key.0.as_slice()));
    assert_eq!(ptr, payload_ptr);
    assert_eq!(ctr, U256::zero());
    assert_eq!(
        scaled_next_pos,
        (Segment::StorageLinkedList as usize).into()
    );
    let Some([inserted_addr, inserted_key, ptr, ctr, scaled_new_pos]) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(inserted_addr, U256::MAX);
    assert_eq!(inserted_key, U256::zero());
    assert_eq!(ptr, U256::zero());
    assert_eq!(ctr, U256::zero());
    assert_eq!(
        scaled_new_pos,
        (Segment::StorageLinkedList as usize + 5).into()
    );
    Ok(())
}

#[test]
fn test_insert_and_delete_accounts() -> Result<()> {
    init_logger();

    let init_label = KERNEL.global_labels["init_linked_lists"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_account_label = KERNEL.global_labels["insert_account_to_linked_list"];

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
        // Remove addressese already in list.
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

    for (i, [addr, ptr, ctr, _]) in list.enumerate() {
        if addr == U256::MAX {
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

#[test]
fn test_insert_and_delete_storage() -> Result<()> {
    init_logger();

    let init_label = KERNEL.global_labels["init_linked_lists"];

    // Test for address already in list.
    let initial_stack = vec![0xdeadbeefu32.into()];
    let mut interpreter = Interpreter::<F>::new(init_label, initial_stack);
    interpreter.run()?;

    let insert_slot_label = KERNEL.global_labels["insert_slot"];

    let retaddr = 0xdeadbeefu32.into();
    let mut rng = thread_rng();
    let n = 10;
    let mut addresses_and_keys = (0..n)
        // .map(|_| rng.gen::<Address>())
        .map(|i| {
            [
                Address::from_low_u64_be(i as u64 + 5),
                H160::from_low_u64_be(i as u64 + 6),
            ]
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<[H160; 2]>>();
    let delta_ptr = 100;
    // let addr_not_in_list = rng.gen::<Address>();
    let addr_not_in_list = Address::from_low_u64_be(4);
    let key_not_in_list = H160::from_low_u64_be(5);
    assert!(
        !addresses_and_keys.contains(&[addr_not_in_list, key_not_in_list]),
        "Cosmic luck or bad RNG?"
    );

    let offset = Segment::StorageLinkedList as usize;
    // Insert all addresses, key pairs
    for i in 0..n {
        let [addr, key] = addresses_and_keys[i as usize].map(|x| U256::from(x.0.as_slice()));
        interpreter.push(0xdeadbeefu32.into());
        interpreter.push(addr + delta_ptr); // ptr = addr + delta_ptr for the sake of the test
        interpreter.push(key);
        interpreter.push(addr);
        interpreter.generation_state.registers.program_counter = insert_slot_label;
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
                MemoryAddress::new_bundle(U256::from(offset + 5 * (i + 1) + 3)).unwrap(),
            ),
            U256::zero()
        );
    }

    // The next free node in Segment::StorageLinkedList must be at offset + (n +
    // 1)*5.
    assert_eq!(
        interpreter.generation_state.memory.get_with_init(
            MemoryAddress::new_bundle(U256::from(GlobalMetadata::StorageLinkedListLen as usize))
                .unwrap(),
        ),
        U256::from(offset + (n + 1) * 5)
    );

    // Test for address already in list.
    for i in 0..n {
        let [addr_in_list, key_in_list] =
            addresses_and_keys[i as usize].map(|x| U256::from(x.0.as_slice()));
        interpreter.push(retaddr);
        interpreter.push(U256::zero());
        interpreter.push(key_in_list);
        interpreter.push(addr_in_list);
        interpreter.generation_state.registers.program_counter = insert_slot_label;
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
                MemoryAddress::new_bundle(U256::from(offset + 5 * (i + 1) + 3)).unwrap(),
            ),
            U256::one()
        );
    }

    // Test for address not in the list.
    interpreter.push(retaddr);
    interpreter.push(U256::from(addr_not_in_list.0.as_slice()) + delta_ptr);
    interpreter.push(U256::from(key_not_in_list.0.as_slice()));
    interpreter.push(U256::from(addr_not_in_list.0.as_slice()));
    interpreter.generation_state.registers.program_counter = insert_slot_label;

    interpreter.run()?;
    assert_eq!(
        interpreter.pop().expect("The stack can't be empty"),
        U256::zero()
    );
    assert_eq!(
        interpreter.pop().expect("The stack can't be empty"),
        U256::from(addr_not_in_list.0.as_slice()) + delta_ptr
    );

    // Now the list of accounts have [4, 5]
    addresses_and_keys.push([addr_not_in_list, key_not_in_list]);

    // The next free node in Segment::AccounLinkedList must be at offset + (n +
    // 2)*5.
    assert_eq!(
        interpreter.generation_state.memory.get_with_init(
            MemoryAddress::new_bundle(U256::from(GlobalMetadata::StorageLinkedListLen as usize))
                .unwrap(),
        ),
        U256::from(offset + (n + 2) * 5)
    );

    // Remove all even nodes
    let remove_slot_label = KERNEL.global_labels["remove_slot"];

    let mut new_addresses = vec![];

    for (i, j) in (0..n).tuples() {
        // Test for [address, ke] already in list.
        let [addr_in_list, key_in_list] =
            addresses_and_keys[i as usize].map(|x| U256::from(x.0.as_slice()));
        interpreter.push(retaddr);
        interpreter.push(key_in_list);
        interpreter.push(addr_in_list);
        interpreter.generation_state.registers.program_counter = remove_slot_label;
        interpreter.run()?;
        assert!(interpreter.stack().is_empty());
        // we add the non deleted addres to new_addresses
        new_addresses.push(addresses_and_keys[j]);
    }
    // the last address is not removed
    new_addresses.push(*addresses_and_keys.last().unwrap());

    // We need to sort the list in order to properly compare with
    // the linked list the interpreter's memory
    new_addresses.sort();

    let mut list = interpreter
        .generation_state
        .get_storage_linked_list()
        .expect("Since we called init_access_lists there must be a list");

    for (i, [addr, key, ptr, ctr, _]) in list.enumerate() {
        if addr == U256::MAX {
            //
            assert_eq!(addr, U256::MAX);
            assert_eq!(key, U256::zero());
            assert_eq!(ptr, U256::zero());
            assert_eq!(ctr, U256::zero());
            break;
        }
        let [addr_in_list, key_in_list] = new_addresses[i].map(|x| U256::from(x.0.as_slice()));
        assert_eq!(addr, addr_in_list);
        assert_eq!(key, key_in_list);
        assert_eq!(ptr, addr + delta_ptr);
        // ctr is 0 for the lowest address because is never accessed
        assert_eq!(ctr, if i == 0 { U256::zero() } else { U256::one() });
    }

    Ok(())
}
