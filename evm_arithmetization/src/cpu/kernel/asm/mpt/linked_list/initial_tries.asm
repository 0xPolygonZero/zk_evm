
global set_initial_state_trie:
    PUSH set_initial_state_trie_after
    %first_initial_slot // Skip the first node.
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    %first_initial_account // Skip the first node.
    %jump(insert_all_initial_accounts)
set_initial_state_trie_after:
    //stack: new_state_root
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    JUMP

%macro set_initial_state_trie
    // stack: (empty)
    PUSH %%after
    %jump(set_initial_state_trie)
%%after:
%endmacro

// Given a pointer `root_ptr` to the root of a trie, insert all the initial accounts in
// the accounts_linked_list starting at `account_ptr_ptr` as well as the
// respective initial storage slots in `storage_ptr_ptr`.
// Pre stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
// Post stack: new_root_ptr. // The value of new_root_ptr shouldn't change
global insert_all_initial_accounts:
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    SWAP2
    DUP3
    MLOAD_GENERAL
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP4
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    EQ
    %jumpi(no_more_accounts)
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    PUSH after_mpt_read
    DUP2
    PUSH 64
    DUP6
    // stack: root_ptr, nibbles, key, after_mpt_read, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %jump(mpt_read)
after_mpt_read:
    //stack: trie_account_ptr_ptr, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP1
    %mload_trie_data
    %add_const(2)
    %mload_trie_data
    // stack: trie_storage_root, trie_account_ptr_ptr, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    SWAP1
    // stack: trie_account_ptr_ptr, trie_storage_root, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP6
    %add_const(2) // intial account_ptr = account_ptr_ptr + 2
    MLOAD_GENERAL
    // stack: account_ptr, trie_account_ptr_ptr, trie_storage_root, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP1 SWAP2
    // stack: trie_account_ptr_ptr, account_ptr, account_ptr, trie_storage_root, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %mstore_trie_data // The trie's account points to the linked list initial account
    // stack: account_ptr, trie_storage_root, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %add_const(2)
    // stack: storage_root_ptr_ptr, trie_storage_root, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest

    %stack
        (storage_root_ptr_ptr, trie_storage_root, key, storage_ptr_ptr) ->
        (key, storage_ptr_ptr, trie_storage_root, after_insert_all_initial_slots, storage_root_ptr_ptr)
    %jump(insert_all_initial_slots)

after_insert_all_initial_slots:
    // stack: storage_ptr_ptr', trie_storage_root_ptr', storage_root_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    SWAP2
    %mstore_trie_data
    // stack: storage_ptr_ptr', root_ptr, account_ptr_ptr, retdest
    SWAP2
    %next_initial_account
    // stack: account_ptr_ptr', root_ptr, storage_ptr_ptr', retdest
    %jump(insert_all_initial_accounts)

no_more_accounts:
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %stack (key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest) ->(retdest, root_ptr)
    JUMP

// Insert all slots before the account key changes
// Pre stack: addr, storage_ptr_ptr, root_ptr, retdest
// Post stack: storage_ptr_ptr', root_ptr'
global insert_all_initial_slots:
    DUP2
    MLOAD_GENERAL
    DUP2
    EQ // Check that the node address is the same as `addr`
    DUP3
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN)
    SUB
    MUL
    %jumpi(insert_next_slot)
    // The addr has changed, meaning that we've inserted all slots for addr,
    // or we reached the end of the initial storage linked list.
    // stack: addr, storage_ptr_ptr, root_ptr, retdest
    %stack (addr, storage_ptr_ptr, root_ptr, retdest) -> (retdest, storage_ptr_ptr, root_ptr)
    JUMP
insert_next_slot:
    // stack: addr, storage_ptr_ptr, root_ptr, retdest
    DUP2
    %increment
    MLOAD_GENERAL
    // stack: key, addr, storage_ptr_ptr, root_ptr, retdest
    DUP3
    %add_const(3) // inital value is at position 3
    MLOAD_GENERAL
    // stack: value, key, addr, storage_ptr_ptr, root_ptr, retdest
    // If the value is 0, then payload_ptr = 0, and we don't need to insert a value in the `TrieData` segment.
    DUP1 ISZERO %jumpi(insert_with_payload_ptr)
    %get_trie_data_size // payload_ptr
    SWAP1
    %append_to_trie_data // append the value to the trie data segment
insert_with_payload_ptr:
    %stack
        (payload_ptr, key, addr, storage_ptr_ptr, root_ptr) -> 
        (root_ptr, 64, key, after_insert_slot, payload_ptr, storage_ptr_ptr, addr, root_ptr)
    %jump(mpt_read)
after_insert_slot:
    // stack: slot_ptr_ptr, payload_ptr, storage_ptr_ptr, addr, root_ptr, retdest
    %mstore_trie_data
    // stack: storage_ptr_ptr, addr, root_ptr, retdest
    %next_initial_slot
    // stack: storage_ptr_ptr', addr, root_ptr, retdest
    SWAP1
    %jump(insert_all_initial_slots)

