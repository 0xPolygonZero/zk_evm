// Given a pointer `root_ptr` to the root of a trie, insert all accounts in
// the accounts_linked_list starting at `account_ptr_ptr` as well as the
// respective storage slots in `storage_ptr_ptr`.
// Pre stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
// Post stack: new_root_ptr.
global insert_all_accounts:
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    SWAP2
    DUP3
    MLOAD_GENERAL
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP1
    %eq_const(@U256_MAX)
    %jumpi(no_more_accounts)
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    DUP4
    %increment
    MLOAD_GENERAL
    // stack: account_ptr, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %add_const(2)
    DUP1
    %mload_trie_data
    // stack: storage_root_ptr, storage_root_ptr_ptr, key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %stack
        (storage_root_ptr, storage_root_ptr_ptr, key, storage_ptr_ptr) ->
        (key, storage_ptr_ptr, storage_root_ptr, after_insert_all_slots, storage_root_ptr_ptr, key)
    %jump(insert_all_slots)

after_insert_all_slots:
    // stack: storage_ptr_ptr', storage_root_ptr', storage_root_ptr_ptr, key, root_ptr, account_ptr_ptr, retdest
    SWAP2
    %mstore_trie_data
    // stack: storage_ptr_ptr', key, root_ptr, account_ptr_ptr, retdest
    DUP4
    %increment
    MLOAD_GENERAL
    %stack
        (payload_ptr, storage_ptr_ptr_p, key, root_ptr, account_ptr_ptr) -> 
        (root_ptr, 64, key, payload_ptr, after_insert_account, account_ptr_ptr, storage_ptr_ptr_p)
    %jump(mpt_insert)
after_insert_account:
    // stack: root_ptr', account_ptr_ptr, storage_ptr_ptr', retdest
    SWAP1
    %next_account
    // stack: account_ptr_ptr', root_ptr', storage_ptr_ptr', retdest
    %jump(insert_all_accounts)

no_more_accounts:
    // stack: key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest
    %stack (key, storage_ptr_ptr, root_ptr, account_ptr_ptr, retdest) ->(retdest, root_ptr)
    JUMP

// Insert all slots before the account key changes
// Pre stack: addr, storage_ptr_ptr, root_ptr, retdest
// Post stack: storage_ptr_ptr', root_ptr'
global insert_all_slots:
    DUP2
    MLOAD_GENERAL
    DUP2
    EQ // Check that the node addres is the same as `addr`
    %jumpi(insert_next_slot)
    // The addr has changed, meaning that we've inserted all slots for addr
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
    %add_const(2)
    MLOAD_GENERAL
    // stack: value, key, addr, storage_ptr_ptr, root_ptr, retdest
    // If the value is 0, then payload_ptr = 0, and we don't need to insert a value in the `TrieData` segment.
    DUP1 ISZERO %jumpi(insert_with_payload_ptr)
    %get_trie_data_size // payload_ptr
    SWAP1 %append_to_trie_data // append the value to the trie data segment
insert_with_payload_ptr:
    %stack (payload_ptr, key, addr, storage_ptr_ptr, root_ptr) -> (root_ptr, 64, key, payload_ptr, after_insert_slot, storage_ptr_ptr, addr)
    %jump(mpt_insert)
after_insert_slot:
    // stack: root_ptr', storage_ptr_ptr, addr, retdest
    SWAP1
    %next_slot
    // stack: storage_ptr_ptr', root_ptr', addr
    %stack (storage_ptr_ptr_p, root_ptr_p, addr) -> (addr, storage_ptr_ptr_p, root_ptr_p)
    %jump(insert_all_slots)

// Delete all the accounts, referenced by the respective nodes in the linked list starting at 
// `account_ptr_ptr`, which where deleted from the intial state. Delete also all slots of non-deleted accounts 
// deleted from the storage trie.
// Pre stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
// Post stack: new_root_ptr.
global delete_removed_accounts:
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP1
    // We assume that the size of the initial accounts linked list, containing the accounts
    // of the initial state, was stored at `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`.
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    // The inital accounts linked list was stored at addresses smaller than `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`.
    // If we also know that `@SEGMENT_ACCOUNT_LINKED_LIST <= account_ptr_ptr`, for deleting node at `addr_ptr_ptr` it
    // suffices to check that `account_ptr_ptr` != `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`
    EQ
    %jumpi(delete_removed_accounts_end)
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP1
    %next_account
    %eq_const(@U256_MAX) // If the next node pointer is @U256_MAX, the node was deleted
    %jumpi(delete_account)
    // The account is still there so we need to delete any removed slot.
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP1
    MLOAD_GENERAL
    // stack: key, account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP2
    %add_const(2)
    MLOAD_GENERAL // get initial payload_ptr
    %add_const(2) // storage_root_ptr_ptr = payload_ptr + 2
    %mload_trie_data
    // stack: storage_root_ptr, key, account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP3
    %increment
    MLOAD_GENERAL // get dynamic payload_ptr
    %add_const(2) // storage_root_ptr_ptr = dyn_payload_ptr + 2
    %stack
        (storage_root_ptr_ptr, storage_root_ptr, key, account_ptr_ptr, root_ptr, storage_ptr_ptr) ->
        (key, storage_root_ptr, storage_ptr_ptr, after_delete_removed_slots, storage_root_ptr_ptr, account_ptr_ptr, root_ptr)
    %jump(delete_removed_slots)
after_delete_removed_slots:
    // stack: storage_root_ptr', storage_ptr_ptr', storage_root_ptr_ptr, account_ptr_ptr, root_ptr, retdest
    SWAP1 SWAP2
    // stack: storage_root_ptr_ptr, storage_root_ptr', storage_ptr_ptr', account_ptr_ptr, root_ptr, retdest
    %mstore_trie_data
    // stack: storage_ptr_ptr', account_ptr_ptr, root_ptr, retdest
    SWAP1
    %add_const(@ACCOUNTS_LINKED_LISTS_NODE_SIZE) // The next account in memory
    // stack: account_ptr_ptr', storage_ptr_ptr', root_ptr, retdest
    SWAP1 SWAP2 SWAP1
    %jump(delete_removed_accounts)

delete_removed_accounts_end:
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    %stack (account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest) -> (retdest, root_ptr)
    JUMP
delete_account:
    // stack: account_ptr_ptr, root_ptr, storage_ptr_ptr, retdest
    DUP1
    MLOAD_GENERAL
    %stack (key, account_ptr_ptr, root_ptr) -> (root_ptr, 64, key, after_mpt_delete, account_ptr_ptr)
    // Pre stack: node_ptr, num_nibbles, key, retdest
    // Post stack: updated_node_ptr
    %jump(mpt_delete)
after_mpt_delete:
    // stack: root_ptr', account_ptr_ptr, storage_ptr_ptr, retdest
    SWAP1
    %add_const(@ACCOUNTS_LINKED_LISTS_NODE_SIZE)
    %jump(delete_removed_accounts)

// Delete all slots in `storage_ptr_ptr` with address == `addr` and
// `storage_ptr_ptr` < `@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN`.
// Pre stack: addr, root_ptr, storage_ptr_ptr, retdest
// Post stack: new_root_ptr, storage_ptr_ptr'.
delete_removed_slots:
    // stack: addr, root_ptr, storage_ptr_ptr, retdest
    DUP3
    MLOAD_GENERAL
    // stack: address, addr, root_ptr, storage_ptr_ptr, retdest
    DUP2
    EQ
    // stack: loaded_address == addr, addr, root_ptr, storage_ptr_ptr, retdest
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN)
    DUP5
    LT
    MUL // AND
    // stack: loaded_address == addr AND storage_ptr_ptr < GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN, addr, root_ptr, storage_ptr_ptr, retdest
    // jump if we either change the address or reach the end of the initial linked list
    %jumpi(maybe_delete_this_slot)
    // If we are here we have deleted all the slots for this key
    %stack (addr, root_ptr, storage_ptr_ptr, retdest) -> (retdest, root_ptr, storage_ptr_ptr)
    JUMP
maybe_delete_this_slot:
    // stack: addr, root_ptr, storage_ptr_ptr, retdest
    DUP3
    %next_slot
    %eq_const(@U256_MAX) // Check if the node was deleted
    %jumpi(delete_this_slot)
    // The slot was not deleted, so we skip it.
    // stack: addr, root_ptr, storage_ptr_ptr, retdest
    SWAP2
    %add_const(@STORAGE_LINKED_LISTS_NODE_SIZE)
    SWAP2
    %jump(delete_removed_slots)
delete_this_slot:
    // stack: addr, root_ptr, storage_ptr_ptr, retdest
    DUP3
    %increment
    MLOAD_GENERAL
    %stack (key, addr, root_ptr, storage_ptr_ptr) -> (root_ptr, 64, key, after_mpt_delete_slot, addr, storage_ptr_ptr)
    %jump(mpt_delete)
after_mpt_delete_slot:
    // stack: root_ptr', addr, storage_ptr_ptr
    SWAP2
    %add_const(@STORAGE_LINKED_LISTS_NODE_SIZE)
    %stack (storage_ptr_ptr_p, addr, root_ptr_p) -> (addr, root_ptr_p, storage_ptr_ptr_p)
    %jump(delete_removed_slots)

global set_final_tries:
    PUSH set_final_tries_after
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %add_const(@STORAGE_LINKED_LISTS_NODE_SIZE) // Skip the first node.
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %add_const(@ACCOUNTS_LINKED_LISTS_NODE_SIZE) // Skip the first node.
    %jump(delete_removed_accounts)
set_final_tries_after:
    // stack: new_state_root
    PUSH set_final_tries_after_after SWAP1
    // stack: new_state_root, set_final_tries_after_after
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %next_slot
    SWAP1
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_account
    %jump(insert_all_accounts)
set_final_tries_after_after:
    //stack: new_state_root
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    JUMP

%macro set_final_tries
    // stack: (empty)
    PUSH %%after
    %jump(set_final_tries)
%%after:
%endmacro
