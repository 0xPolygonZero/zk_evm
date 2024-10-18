// struct StorageChange { address, slot, prev_value }

%macro journal_add_transient_storage_change
    %journal_add_3(@JOURNAL_ENTRY_TRANSIENT_STORAGE_CHANGE)
%endmacro

global revert_transient_storage_change:
    // stack: entry_type, ptr, retdest
    POP
    %journal_load_3
    // We will always write 0 for deletions as it makes no difference.
    // stack: addr, slot, prev_value, retdest
    %search_transient_storage
    // stack: found, pos, addr, value, slot, prev_value, retdest
    // The value must have been stored
    %assert_nonzero
    // stack: pos, addr, value, slot, prev_value, retdest
    %add_const(2)
    DUP5
    // stack: prev_value, pos+2, addr, value, slot, prev_value, retdest
    MSTORE_GENERAL
    %pop4
    JUMP
