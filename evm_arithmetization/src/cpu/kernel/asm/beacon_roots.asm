/// EIP-4788: Beacon block root in the EVM

global set_beacon_root:
    PUSH start_txn
    %timestamp
    // stack: timestamp, start_txns
    PUSH @HISTORY_BUFFER_LENGTH
    DUP2
    // stack: timestamp, mod, timestamp, start_txns
    MOD
    // stack: timestamp_idx, timestamp, start_txns
    PUSH write_beacon_roots_to_storage
    %parent_beacon_block_root
    // stack: calldata, write_beacon_roots_to_storage, timestamp_idx, timestamp, start_txns
    DUP2
    PUSH @HISTORY_BUFFER_LENGTH
    ADD
    // stack: root_idx, calldata, write_beacon_roots_to_storage, timestamp_idx, timestamp, start_txns

write_beacon_roots_to_storage:
    // stack: slot, value, retdest
     // First we write the value to MPT data, and get a pointer to it.
    %get_trie_data_size
    // stack: value_ptr, slot, value, retdest
    SWAP2
    // stack: value, slot, value_ptr, retdest
    %append_to_trie_data
    // stack: slot, value_ptr, retdest

    // Next, call mpt_insert on the current account's storage root.
    %stack (slot, value_ptr) -> (slot, value_ptr, after_beacon_roots_storage_insert)
    %slot_to_storage_key
    // stack: storage_key, value_ptr, after_beacon_roots_storage_insert, retdest
    PUSH 64 // storage_key has 64 nibbles
    %get_storage_trie(@BEACON_ROOTS_ADDRESS)
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_beacon_roots_storage_insert, retdest
    %jump(mpt_insert)

after_beacon_roots_storage_insert:
    // stack: new_storage_root_ptr, retdest
    %current_account_data
    // stack: account_ptr, new_storage_root_ptr, retdest

    // Update the copied account with our new storage root pointer.
    %add_const(2)
    // stack: account_storage_root_ptr_ptr, new_storage_root_ptr, retdest
    %mstore_trie_data
    JUMP

skip_beacon_roots_update:
    // stack: account_ptr, 64, storage_key, value_ptr, after_beacon_roots_storage_insert, retdest
    %pop5
    JUMP