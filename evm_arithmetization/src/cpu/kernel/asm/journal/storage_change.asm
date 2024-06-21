// struct StorageChange { address, slot, prev_value }

%macro journal_add_storage_change
    %journal_add_3(@JOURNAL_ENTRY_STORAGE_CHANGE)
%endmacro

global revert_storage_change:
    // stack: entry_type, ptr, retdest
    POP
    %journal_load_3
    // stack: address, slot, prev_value, retdest
    DUP3 ISZERO %jumpi(delete)
    // stack: address, slot, prev_value, retdest
    %read_slot_linked_list
    // stack: cold_access, value_ptr, prev_value, retdest
    POP DUP1 %assert_nonzero
    // stack: value_ptr, prev_value, retdest
    %mstore_trie_data
    JUMP

delete:
    // stack: address, slot, prev_value, retdest
    SWAP2 POP
    // stack: slot, address, retdest
    %slot_to_storage_key
    SWAP1 %addr_to_state_key
    // stack: addr_key, slot_key, retdest
    %jump(remove_slot)
