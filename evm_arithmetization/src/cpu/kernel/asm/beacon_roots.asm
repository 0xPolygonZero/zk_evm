/// EIP-4788: Beacon block root in the EVM
/// <https://eips.ethereum.org/EIPS/eip-4788#pseudocode>
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

global set_beacon_root:
    PUSH set_global_exit_roots
    %timestamp
    // stack: timestamp, retdest
    PUSH @HISTORY_BUFFER_LENGTH
    DUP2
    // stack: timestamp, 8191, timestamp, retdest
    MOD
    // stack: timestamp_idx, timestamp, retdest
    PUSH write_beacon_roots_to_storage
    %parent_beacon_block_root
    // stack: calldata, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    DUP3
    %add_const(@HISTORY_BUFFER_LENGTH)
    // stack: root_idx, calldata, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest

    // If the calldata is zero, delete the slot from the storage trie.
    DUP2 ISZERO %jumpi(delete_root_idx_slot)

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
    %get_storage_trie(@BEACON_ROOTS_CONTRACT_STATE_KEY)
    // stack: storage_root_ptr, 64, storage_key, value_ptr, after_beacon_roots_storage_insert, retdest
    %jump(mpt_insert)

after_beacon_roots_storage_insert:
    // stack: new_storage_root_ptr, retdest
    %get_account_data(@BEACON_ROOTS_CONTRACT_STATE_KEY)
    // stack: account_ptr, new_storage_root_ptr, retdest

    // Update the copied account with our new storage root pointer.
    %add_const(2)
    // stack: account_storage_root_ptr_ptr, new_storage_root_ptr, retdest
    %mstore_trie_data
    JUMP

delete_root_idx_slot:
    // stack: root_idx, 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    PUSH after_root_idx_slot_delete
    SWAP2 POP
    // stack: root_idx, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %slot_to_storage_key
    // stack: storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    PUSH 64 // storage_key has 64 nibbles
    %get_storage_trie(@BEACON_ROOTS_CONTRACT_STATE_KEY)
    // stack: storage_root_ptr, 64, storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest

    // If the slot is empty (i.e. ptr defaulting to 0), skip the deletion.
    DUP1 ISZERO %jumpi(skip_empty_slot)

    // stack: storage_root_ptr, 64, storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %stack (storage_root_ptr, nibbles, storage_key) -> (storage_root_ptr, nibbles, storage_key, checkpoint_delete_root_idx, storage_root_ptr, nibbles, storage_key)
    %jump(mpt_read)
checkpoint_delete_root_idx:
    // stack: value_ptr, storage_root_ptr, 64, storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    // If the the storage key is not found (i.e. ptr defaulting to 0), skip the deletion.
    ISZERO %jumpi(skip_empty_slot)

    // stack: storage_root_ptr, 64, storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %jump(mpt_delete)

after_root_idx_slot_delete:
    // stack: new_storage_root_ptr, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %get_account_data(@BEACON_ROOTS_CONTRACT_STATE_KEY)
    // stack: account_ptr, new_storage_root_ptr, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest

    // Update the copied account with our new storage root pointer.
    %add_const(2)
    // stack: account_storage_root_ptr_ptr, new_storage_root_ptr, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %mstore_trie_data
    // stack: write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    JUMP

skip_empty_slot:
    // stack: 0, 64, storage_key, after_root_idx_slot_delete, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %pop4
    JUMP
