// struct NonceChange { address, prev_nonce }

%macro journal_add_nonce_change
    %journal_add_2(@JOURNAL_ENTRY_NONCE_CHANGE)
%endmacro

global revert_nonce_change:
    // stack: entry_type, ptr, retdest
    POP
    %journal_load_2
    // stack: address, prev_nonce, retdest
    %search_account
    // stack: found_address, payload_ptr, prev_nonce, retdest
    %assert_zero // The address should already be present.
    // stack: nonce_ptr, prev_nonce retdest
    %mstore_trie_data
    // stack: retdest
    JUMP

