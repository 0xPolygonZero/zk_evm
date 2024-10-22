// Write a word to the current account's storage trie.
//
// Pre stack: kexit_info, slot, value
// Post stack: (empty)

global sys_sstore:
    %check_static
    DUP1 %leftover_gas %le_const(@GAS_CALLSTIPEND) %jumpi(fault_exception)
    %stack (kexit_info, slot, value) -> (slot, kexit_info, slot, value)
    %sload_current
    %address
    %stack (addr, current_value, kexit_info, slot, value) -> (addr, slot, current_value, kexit_info, slot, value)
    %insert_accessed_storage_keys
    // stack: cold_access, value_ptr, current_value, kexit_info, slot, value
    %jumpi(sstore_cold_access)
    // stack: value_ptr, current_value, kexit_info, slot, value
    MLOAD_GENERAL
    // stack: original_value, current_value, kexit_info, slot, value
    PUSH 0
    // stack: gas, original_value, current_value, kexit_info, slot, value
    %jump(sstore_after_cold_access_check)

sstore_cold_access:
    // stack: value_ptr, current_value, kexit_info, slot, value
    DUP2 MSTORE_GENERAL
    // stack: current_value, kexit_info, slot, value
    DUP1
    PUSH @GAS_COLDSLOAD
    // stack: gas, original_value, current_value, kexit_info, slot, value

sstore_after_cold_access_check:
    // Check for warm access.
    %stack (gas, original_value, current_value, kexit_info, slot, value) ->
        (value, current_value, current_value, original_value, gas, original_value, current_value, kexit_info, slot, value)
    EQ SWAP2 EQ ISZERO
    // stack: current_value==original_value, value==current_value, gas, original_value, current_value, kexit_info, slot, value)
    ADD // OR
    %jumpi(sstore_warm)

    // Check for sset (set a zero storage slot to a non-zero value).
    // stack: gas, original_value, current_value, kexit_info, slot, value
    DUP2 ISZERO %mul_const(@GAS_SSET) ADD

    // Check for sreset (set a non-zero storage slot to a non-zero value).
    // stack: gas, original_value, current_value, kexit_info, slot, value
    DUP2 ISZERO ISZERO %mul_const(@GAS_SRESET) ADD
    %jump(sstore_charge_gas)

sstore_warm:
    // stack: gas, original_value, current_value, kexit_info, slot, value)
    %add_const(@GAS_WARMACCESS)

sstore_charge_gas:
    %stack (gas, original_value, current_value, kexit_info, slot, value) -> (gas, kexit_info, current_value, value, original_value, slot)
    %charge_gas

sstore_refund:
    %stack (kexit_info, current_value, value, original_value, slot) -> (current_value, value, current_value, value, original_value, slot, kexit_info)
    EQ %jumpi(sstore_no_refund)
    %stack (current_value, value, original_value, slot, kexit_info) -> (current_value, original_value, current_value, value, original_value, slot, kexit_info)
    EQ %jumpi(sstore_refund_original)
    %stack (current_value, value, original_value, slot, kexit_info) -> (original_value, current_value, value, original_value, slot, kexit_info)
    ISZERO %jumpi(sstore_dirty_reset)
    %stack (current_value, value, original_value, slot, kexit_info) -> (current_value, current_value, value, original_value, slot, kexit_info)
    ISZERO %jumpi(sstore_dirty_clear1)
    %stack (current_value, value, original_value, slot, kexit_info) -> (value, current_value, value, original_value, slot, kexit_info)
    ISZERO %jumpi(sstore_dirty_clear2)
    %jump(sstore_dirty_reset)

sstore_dirty_clear1:
    PUSH @REFUND_SCLEAR PUSH 0 SUB %refund_gas
    %jump(sstore_dirty_reset)

sstore_dirty_clear2:
    PUSH @REFUND_SCLEAR %refund_gas

sstore_dirty_reset:
    %stack (current_value, value, original_value, slot, kexit_info) -> (original_value, value, current_value, value, original_value, slot, kexit_info)
    EQ %jumpi(sstore_dirty_reset2)
    %jump(sstore_no_refund)
sstore_dirty_reset2:
    %stack (current_value, value, original_value, slot, kexit_info) -> (original_value, current_value, value, original_value, slot, kexit_info)
    ISZERO %jumpi(sstore_dirty_reset_sset)
    PUSH @GAS_WARMACCESS PUSH @GAS_SRESET SUB %refund_gas
    %jump(sstore_no_refund)
sstore_dirty_reset_sset:
    PUSH @GAS_WARMACCESS PUSH @GAS_SSET SUB %refund_gas
    %jump(sstore_no_refund)

sstore_refund_original:
    %stack (current_value, value, original_value, slot, kexit_info) -> (value, current_value, value, original_value, slot, kexit_info)
    ISZERO %jumpi(sstore_sclear)
    %jump(sstore_no_refund)
sstore_sclear:
    PUSH @REFUND_SCLEAR %refund_gas
    %jump(sstore_no_refund)

sstore_no_refund:
    %stack (current_value, value, original_value, slot, kexit_info) -> (kexit_info, current_value, slot, value)
sstore_after_refund:
    // stack: kexit_info, current_value, slot, value
    // Check if `value` is equal to `current_value`, and if so exit the kernel early.
    %stack (kexit_info, current_value, slot, value) -> (value, current_value, current_value, slot, value, kexit_info)
    EQ %jumpi(sstore_noop)

    // stack: current_value, slot, value, kexit_info
    DUP1 ISZERO
    // stack: current_value==0, current_value, slot, value, kexit_info
    DUP4 MUL
    // stack: value & current_value==0, current_value, slot, value, kexit_info
    %jumpi(new_storage_slot)
global not_new_storage_slot:

    // stack: current_value, slot, value, kexit_info
    DUP2 %address %journal_add_storage_change
    // stack: slot, value, kexit_info

    // If the value is zero, delete the slot from the storage trie.
    // stack: slot, value, kexit_info
    DUP2 ISZERO %jumpi(sstore_delete)


    // stack: slot, value, kexit_info
    %address
    %insert_slot

    EXIT_KERNEL

sstore_noop:
    // stack: current_value, slot, value, kexit_info
    %pop3
    EXIT_KERNEL

// Delete the slot from the storage trie.
sstore_delete:
    // stack: slot, value, kexit_info
    %address
    // stack: addr, slot, value, kexit_info
    %remove_slot_from_addr
    // stack: value, kexit_info
    POP
    EXIT_KERNEL

%macro insert_new_storage_slot
    // stack: address, slot
    %mload_global_metadata(@GLOBAL_METADATA_NEW_STORAGE_SLOTS_LEN)
    // stack: list_len, address, slot
    DUP1 %add_const(@SEGMENT_NEW_STORAGE_SLOTS)
    // stack: index, list_len, address, slot
    DUP1 %add_const(1)
    %stack (index_plus_1, index, list_len, address, slot) -> (address, index, slot, index_plus_1, list_len)
    MSTORE_GENERAL MSTORE_GENERAL
    // stack: list_len
    %add_const(2)
    // stack: list_len+2
    %mstore_global_metadata(@GLOBAL_METADATA_NEW_STORAGE_SLOTS_LEN)
    // stack: (empty)
%endmacro

new_storage_slot:
    // stack: current_value, slot, value, kexit_info
    %address DUP1 %contract_just_created
    // stack: contract_just_created, address, current_value, slot, value, kexit_info
    %jumpi(new_storage_slot_new_contract)
    // stack: address, current_value, slot, value, kexit_info
    POP %jump(not_new_storage_slot)
new_storage_slot_new_contract:
    // stack: address, current_value, slot, value, kexit_info
    DUP3 SWAP1
    // stack: address, slot, current_value, slot, value, kexit_info
    %insert_new_storage_slot
    // stack: current_value, slot, value, kexit_info
    %jump(not_new_storage_slot)
