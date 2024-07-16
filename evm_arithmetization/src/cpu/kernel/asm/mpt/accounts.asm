// Return a pointer to the current account's data in the state trie.
%macro current_account_data
    %address %mpt_read_state_trie
    // stack: account_ptr
    // account_ptr should be non-null as long as the prover provided the proper
    // Merkle data. But a bad prover may not have, and we don't want return a
    // null pointer for security reasons.
    DUP1 ISZERO %jumpi(panic)
    // stack: account_ptr
%endmacro

// Returns a pointer to the root of the storage trie associated with the current account.
%macro current_storage_trie
    // stack: (empty)
    %current_account_data
    // stack: account_ptr
    %add_const(2)
    // stack: storage_root_ptr_ptr
    %mload_trie_data
    // stack: storage_root_ptr
%endmacro

%macro clone_account
    // stack: account_ptr
    %get_trie_data_size
    // stack: cloned_accouint_ptr
    SWAP1
    DUP1
    // Balance
    %mload_trie_data
    %append_to_trie_data
    %increment
    // Nonce
    %increment
    DUP1
    %mload_trie_data
    %append_to_trie_data
    // Storage trie root
    %increment
    DUP1
    %mload_trie_data
    %append_to_trie_data
    // Codehash 
    %increment
    %mload_trie_data
    %append_to_trie_data
    // stack: cloned_account_ptr
%endmacro

// The slot_ptr cannot be 0, because `insert_slot` 
// is only called in `revert_storage_change` (where the case `slot_ptr = 0` 
// is dealt with differently), and in `storage_write`, 
// where writing 0 actually corresponds to a `delete`.
%macro clone_slot
    // stack: slot_ptr
    DUP1 %assert_nonzero
    %get_trie_data_size
    // stack: cloned_slot_ptr, slot_ptr
    SWAP1
    %mload_trie_data
    %append_to_trie_data
%endmacro
