%macro clone_account
    // stack: account_ptr
    %get_trie_data_size
    // stack: cloned_account_ptr
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
    %get_trie_data_size
    // stack: cloned_slot_ptr, slot_ptr
    SWAP1
    %mload_trie_data
    %append_to_trie_data
%endmacro
