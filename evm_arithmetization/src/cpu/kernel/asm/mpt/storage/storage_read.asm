%macro sload_current
    %stack (slot) -> (slot, %%after)
    %jump(sload_current)
%%after:
%endmacro

global sload_current:
    %read_storage_linked_list
    // stack: value_ptr, retdest
    DUP1 %jumpi(storage_key_exists)

    // Storage key not found. Return default value_ptr = 0,
    // which derefs to 0 since @SEGMENT_TRIE_DATA[0] = 0.
    %stack (value_ptr, retdest) -> (retdest, 0)
    
    JUMP

storage_key_exists:
    // stack: value_ptr, retdest
    %mload_trie_data
    // stack: value, retdest
    SWAP1
    JUMP

// Read a word from the current account's storage trie.
//
// Pre stack: kexit_info, slot
// Post stack: value

global sys_sload:
    // stack: kexit_info, slot
    SWAP1
    DUP1
    // stack: slot, slot, kexit_info
    %address
    // stack: address, slot, slot, kexit_info
    %insert_accessed_storage_keys
    // stack: cold_access, value_ptr, slot, kexit_info
    DUP1
    %mul_const(@GAS_COLDSLOAD_MINUS_WARMACCESS)
    %add_const(@GAS_WARMACCESS)
    %stack (gas, cold_access, value_ptr, slot, kexit_info) -> (gas, kexit_info, cold_access, value_ptr, slot)
    %charge_gas

    %stack (kexit_info, cold_access, value_ptr, slot) -> (slot, cold_access, value_ptr, kexit_info)
    %sload_current
    // stack: value, cold_access, value_ptr, kexit_info
    SWAP1 %jumpi(sload_cold_access)
    %stack (value, value_ptr, kexit_info) -> (kexit_info, value)
    EXIT_KERNEL

sload_cold_access:
    // stack: value, value_ptr, kexit_info
    %stack (value, value_ptr, kexit_info) -> (value, value_ptr, kexit_info, value)
    MSTORE_GENERAL
    EXIT_KERNEL
