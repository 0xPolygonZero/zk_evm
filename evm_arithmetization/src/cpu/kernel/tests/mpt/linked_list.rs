use std::collections::HashSet;

use anyhow::Result;
use env_logger::try_init_from_env;
use env_logger::Env;
use env_logger::DEFAULT_FILTER_ENV;
use ethereum_types::{Address, H160, U256};
use plonky2::field::goldilocks_field::GoldilocksField as F;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata::{
    AccessedAddressesLen, AccessedStorageKeysLen,
};
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

    let Some((pos_0, next_val_0, _)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(pos_0, 0);
    assert_eq!(next_val_0, U256::MAX);
    let Some((pos_0, _, _)) = list.next() else {
        return Err(anyhow::Error::msg("Couldn't get value"));
    };
    assert_eq!(pos_0, 0);
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

    let insert_accessed_addresses = KERNEL.global_labels["insert_account"];

    let retaddr = 0xdeadbeefu32.into();
    let mut rng = thread_rng();
    let address: H160 = rng.gen();
    let payload_otr = U256::one();

    assert!(address != H160::zero(), "Cosmic luck or bad RNG?");

    interpreter.push(retaddr);
    interpreter.push(U256::from(address.0.as_slice()));
    interpreter.generation_state.registers.program_counter = insert_accessed_addresses;

    interpreter.run()?;
    assert_eq!(interpreter.stack(), &[U256::one()]);
    assert_eq!(
        interpreter.generation_state.memory.get_with_init(
            MemoryAddress::new_bundle(U256::from(AccessedAddressesLen as usize)).unwrap(),
        ),
        U256::from(Segment::AccessedAddresses as usize + 4)
    );

    Ok(())
}

// #[test]
// fn test_insert_accessed_addresses() -> Result<()> {
//     let init_access_lists = KERNEL.global_labels["init_access_lists"];

//     // Test for address already in list.
//     let initial_stack = vec![0xdeadbeefu32.into()];
//     let mut interpreter = Interpreter::<F>::new(init_access_lists,
// initial_stack);     interpreter.run()?;

//     let insert_accessed_addresses =
// KERNEL.global_labels["insert_accessed_addresses"];

//     let retaddr = 0xdeadbeefu32.into();
//     let mut rng = thread_rng();
//     let n = 10;
//     let addresses = (0..n)
//         .map(|_| rng.gen::<Address>())
//         .collect::<HashSet<_>>()
//         .into_iter()
//         .collect::<Vec<Address>>();
//     let addr_not_in_list = rng.gen::<Address>();
//     assert!(
//         !addresses.contains(&addr_not_in_list),
//         "Cosmic luck or bad RNG?"
//     );

//     let offset = Segment::AccessedAddresses as usize;
//     for i in 0..n {
//         let addr = U256::from(addresses[i].0.as_slice());
//         interpreter.push(0xdeadbeefu32.into());
//         interpreter.push(addr);
//         interpreter.generation_state.registers.program_counter =
// insert_accessed_addresses;         interpreter.run()?;
//         assert_eq!(interpreter.pop().unwrap(), U256::one());
//     }

//     for i in 0..n {
//         // Test for address already in list.
//         let addr_in_list = addresses[i];
//         interpreter.push(retaddr);
//         interpreter.push(U256::from(addr_in_list.0.as_slice()));
//         interpreter.generation_state.registers.program_counter =
// insert_accessed_addresses;         interpreter.run()?;
//         assert_eq!(interpreter.pop().unwrap(), U256::zero());
//         assert_eq!(
//             interpreter.generation_state.memory.get_with_init(
//                 MemoryAddress::new_bundle(U256::from(AccessedAddressesLen as
// usize)).unwrap(),             ),
//             U256::from(offset + 2 * (n + 1))
//         );
//     }

//     // Test for address not in list.
//     interpreter.push(retaddr);
//     interpreter.push(U256::from(addr_not_in_list.0.as_slice()));
//     interpreter.generation_state.registers.program_counter =
// insert_accessed_addresses;

//     interpreter.run()?;
//     assert_eq!(interpreter.stack(), &[U256::one()]);
//     assert_eq!(
//         interpreter.generation_state.memory.get_with_init(
//             MemoryAddress::new_bundle(U256::from(AccessedAddressesLen as
// usize)).unwrap(),         ),
//         U256::from(offset + 2 * (n + 2))
//     );
//     assert_eq!(
//         interpreter
//             .generation_state
//             .memory
//             .get_with_init(MemoryAddress::new(0, AccessedAddresses, 2 * (n +
// 1)),),         U256::from(addr_not_in_list.0.as_slice())
//     );

//     Ok(())
// }

// #[test]
// fn test_insert_accessed_storage_keys() -> Result<()> {
//     let init_access_lists = KERNEL.global_labels["init_access_lists"];

//     // Test for address already in list.
//     let initial_stack = vec![0xdeadbeefu32.into()];
//     let mut interpreter = Interpreter::<F>::new(init_access_lists,
// initial_stack);     interpreter.run()?;

//     let insert_accessed_storage_keys =
// KERNEL.global_labels["insert_accessed_storage_keys"];

//     let retaddr = 0xdeadbeefu32.into();
//     let mut rng = thread_rng();
//     let n = 10;
//     let storage_keys = (0..n)
//         .map(|_| (rng.gen::<Address>(), U256(rng.gen())))
//         .collect::<HashSet<_>>()
//         .into_iter()
//         .collect::<Vec<(Address, U256)>>();
//     let storage_key_not_in_list = (rng.gen::<Address>(), U256(rng.gen()));
//     assert!(
//         !storage_keys.contains(&storage_key_not_in_list),
//         "Cosmic luck or bad RNG?"
//     );

//     let offset = Segment::AccessedStorageKeys as usize;
//     for i in 0..n {
//         let addr = U256::from(storage_keys[i].0 .0.as_slice());
//         let key = storage_keys[i].1;
//         interpreter.push(retaddr);
//         interpreter.push(key);
//         interpreter.push(addr);
//         interpreter.generation_state.registers.program_counter =
// insert_accessed_storage_keys;         interpreter.run()?;
//         assert_eq!(interpreter.pop().unwrap(), U256::one());
//         interpreter.pop().expect("Stack shouldn't be empty"); // Pop the
// value_ptr.     }

//     for i in 0..10 {
//         // Test for storage key already in list.
//         let (addr, key) = storage_keys[i];
//         interpreter.push(retaddr);
//         interpreter.push(key);
//         interpreter.push(U256::from(addr.0.as_slice()));
//         interpreter.generation_state.registers.program_counter =
// insert_accessed_storage_keys;         interpreter.run()?;
//         assert_eq!(interpreter.pop().unwrap(), U256::zero());
//         interpreter.pop().expect("Stack shouldn't be empty"); // Pop the
// value_ptr.         assert_eq!(
//             interpreter.generation_state.memory.get_with_init(
//                 MemoryAddress::new_bundle(U256::from(AccessedStorageKeysLen
// as usize)).unwrap(),             ),
//             U256::from(offset + 4 * (n + 1))
//         );
//     }

//     // Test for storage key not in list.
//     interpreter.push(retaddr);
//     interpreter.push(storage_key_not_in_list.1);
//     interpreter.push(U256::from(storage_key_not_in_list.0 .0.as_slice()));
//     interpreter.generation_state.registers.program_counter =
// insert_accessed_storage_keys;

//     interpreter.run()?;
//     assert_eq!(interpreter.stack()[1], U256::one());
//     assert_eq!(
//         interpreter.generation_state.memory.get_with_init(
//             MemoryAddress::new_bundle(U256::from(AccessedStorageKeysLen as
// usize)).unwrap(),         ),
//         U256::from(offset + 4 * (n + 2))
//     );
//     assert_eq!(
//         interpreter
//             .generation_state
//             .memory
//             .get_with_init(MemoryAddress::new(0, AccessedStorageKeys, 4 * (n
// + 1)),),         U256::from(storage_key_not_in_list.0 .0.as_slice()) );
//   assert_eq!( interpreter .generation_state .memory
//   .get_with_init(MemoryAddress::new(0, AccessedStorageKeys, 4 * (n
// + 1) + 1),),         storage_key_not_in_list.1 );

//     Ok(())
// }
