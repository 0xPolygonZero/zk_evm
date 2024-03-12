/// At the top of the block, the global exit roots (if any) are written to storage.
/// Global exit roots (GER) are of the form `(timestamp, root)` and are loaded from prover inputs.
/// The timestamp is written to the storage of address `ADDRESS_GLOBAL_EXIT_ROOT_MANAGER_L2` in the slot `keccak256(abi.encodePacked(root, GLOBAL_EXIT_ROOT_STORAGE_POS))`.
/// See https://github.com/0xPolygonHermez/cdk-erigon/blob/zkevm/zk/utils/global_exit_root.go for reference.
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

global set_global_exit_roots:
    // stack: (empty)
    PUSH start_txn
    // stack: retdest
    PROVER_INPUT(ger)
    // stack: num_ger, retdest
    PUSH 0
ger_loop:
    // stack: i, num_ger, retdest
    DUP2 DUP2 EQ %jumpi(ger_loop_end)
    PROVER_INPUT(ger)
    // stack: timestamp, i, num_ger, retdest
    PUSH @GLOBAL_EXIT_ROOT_STORAGE_POS
    PROVER_INPUT(ger)
    // stack: root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, retdest
    PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, retdest
    MSTORE_32BYTES_32
    // stack: addr, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, retdest
    MSTORE_32BYTES_32
    // stack: addr, timestamp, i, num_ger, retdest
    POP
    // stack: timestamp, i, num_ger, retdest
    PUSH 64 PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, len, timestamp, i, num_ger, retdest
    KECCAK_GENERAL
    // stack: slot, timestamp, i, num_ger, retdest

write_timestamp_to_storage:
    // stack: slot, timestamp, i, num_ger, retdest
    // First we write the value to MPT data, and get a pointer to it.
    %get_trie_data_size
    // stack: value_ptr, slot, timestamp, i, num_ger, retdest
    SWAP2
    // stack: timestamp, slot, value_ptr, i, num_ger, retdest
    %append_to_trie_data
    // stack: slot, value_ptr, i, num_ger, retdest

    // Next, call mpt_insert on the current account's storage root.
    %stack (slot, value_ptr) -> (slot, value_ptr, after_timestamp_storage_insert)
    %slot_to_storage_key
    // stack: storage_key, value_ptr, after_timestamp_storage_insert
    PUSH 64 // storage_key has 64 nibbles
    %get_storage_trie(@ADDRESS_GLOBAL_EXIT_ROOT_MANAGER_L2)
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_timestamp_storage_insert
    %stack (storage_root_ptr, num_nibbles, storage_key) -> (storage_root_ptr, num_nibbles, storage_key, after_read, storage_root_ptr, num_nibbles, storage_key)
    %jump(mpt_read)
after_read:
    // If the current value is non-zero, do nothing.
    // stack: current_value_ptr, storage_root_ptr, 64, storage_key, value_ptr, after_timestamp_storage_insert
    %mload_trie_data %jumpi(do_nothing)
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_timestamp_storage_insert
    %jump(mpt_insert)

after_timestamp_storage_insert:
    // stack: new_storage_root_ptr, i, num_ger, retdest
    %get_account_data(@ADDRESS_GLOBAL_EXIT_ROOT_MANAGER_L2)
    // stack: account_ptr, new_storage_root_ptr
    // Update the copied account with our new storage root pointer.
    %add_const(2)
    // stack: account_storage_root_ptr_ptr, new_storage_root_ptr
    %mstore_trie_data

    // stack: i, num_ger, retdest
    %increment
    %jump(ger_loop)

ger_loop_end:
    // stack: i, num_ger, retdest
    %pop2 JUMP

do_nothing:
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_timestamp_storage_insert, i, num_ger, retdest
    %pop7
    // stack: retdest
    JUMP
