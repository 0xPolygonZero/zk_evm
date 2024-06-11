// struct CodeChange { address, prev_codehash }

%macro journal_add_code_change
    %journal_add_2(@JOURNAL_ENTRY_CODE_CHANGE)
%endmacro

global revert_code_change:
    // stack: entry_ptr, ptr, retdest
    POP
    %journal_load_2
    // stack: address, prev_codehash, retdest
    %read_accounts_linked_list
    // stack: address_found, account_ptr, prev_codehash, retdest
    %assert_eq_const(1)
    // stack: account_ptr, prev_codehash, retdest
    %add_const(3)
    // stack: codehash_ptr, prev_codehash, retdest
    %mstore_trie_data
    // stack: retdest
    JUMP
