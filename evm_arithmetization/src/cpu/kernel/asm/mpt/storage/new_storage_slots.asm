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

global new_storage_slot:
    // stack: current_value, slot, value, kexit_info
    %address DUP1 %contract_just_created
    // stack: contract_just_created, address, current_value, slot, value, kexit_info
    %jumpi(new_storage_slot_new_contract)
    // stack: address, current_value, slot, value, kexit_info
    POP %jump(not_new_storage_slot)
global new_storage_slot_new_contract:
    // stack: address, current_value, slot, value, kexit_info
    DUP3 SWAP1
    // stack: address, slot, current_value, slot, value, kexit_info
    %insert_new_storage_slot
    // stack: current_value, slot, value, kexit_info
    %jump(not_new_storage_slot)
