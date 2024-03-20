%macro sload_current
    %stack (slot) -> (slot, %%after)
    %jump(sload_current)
%%after:
%endmacro

global sload_current:
    %stack (slot) -> (slot, after_storage_read)
    %slot_to_storage_key
    // stack: storage_key, after_storage_read
    PUSH 64 // storage_key has 64 nibbles
    %current_storage_trie
    // stack: storage_root_ptr, 64, storage_key, after_storage_read
    %jump(mpt_read)

global after_storage_read:
    // stack: value_ptr, retdest
    DUP1 %jumpi(storage_key_exists)

    // Storage key not found. Return default value_ptr = 0,
    // which derefs to 0 since @SEGMENT_TRIE_DATA[0] = 0.
    %stack (value_ptr, retdest) -> (retdest, 0)
    JUMP

global storage_key_exists:
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
    %mul_const(@GAS_COLDSLOAD_MINUS_WARMACCESS)
    %add_const(@GAS_WARMACCESS)
    %stack (gas, value_ptr, slot, kexit_info) -> (gas, kexit_info, value_ptr, slot)
    %charge_gas

    %stack (kexit_info, value_ptr, slot) -> (slot, value_ptr, kexit_info)
    %sload_current
    %stack (value, value_ptr, kexit_info) -> (value, value_ptr, kexit_info, value)
    MSTORE_GENERAL
    // stack: kexit_info, value
    EXIT_KERNEL
