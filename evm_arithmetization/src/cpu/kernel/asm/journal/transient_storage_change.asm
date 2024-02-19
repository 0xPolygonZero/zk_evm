// struct StorageChange { address, slot, prev_value }

%macro journal_add_transient_storage_change
    %journal_add_3(@JOURNAL_ENTRY_TRANSIENT_STORAGE_CHANGE)
%endmacro

global revert_transient_storage_change:
    // stack: entry_type, ptr, retdest
    POP
    %journal_load_3
    // We will always write a new value since for
    // deletions it doesn't make any difference
    // stack: address, slot, prev_value, retdest
    %search_transient_storage
    // The value must have been stored
    %assert_nonzero
    // stack: pos, addr, original_value, prev_value, retdest
    %add_const(2)
    DUP4
    // 
    MSTORE_GENERAL
    %pop2
    JUMP