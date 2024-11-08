// struct CodeChange { address, prev_codehash }

%macro journal_add_code_change
    #[cfg(not(feature = cdk_erigon))]
    {
        %journal_add_2(@JOURNAL_ENTRY_CODE_CHANGE)
    }
    #[cfg(feature = cdk_erigon)]
    {
        %journal_add_3(@JOURNAL_ENTRY_CODE_CHANGE)
    }
%endmacro

global revert_code_change:
    #[cfg(not(feature = cdk_erigon))]
    {
        // stack: entry_ptr, ptr, retdest
        POP
        %journal_load_2
        // stack: address, prev_codehash, retdest
        %read_account_from_addr
        // stack: account_ptr, prev_codehash, retdest
        DUP1 %assert_nonzero
        // stack: account_ptr, prev_codehash, retdest
        %add_const(3)
        // stack: codehash_ptr, prev_codehash, retdest
        %mstore_trie_data
        // stack: retdest
        JUMP
    }
    #[cfg(feature = cdk_erigon)]
    {
        // stack: entry_ptr, ptr, retdest
        POP
        %journal_load_3
        %stack (address, prev_codehash, prev_code_length) -> (address, prev_codehash, address, prev_code_length)
        %set_code
        %set_code_length
        // stack: retdest
        JUMP
    }
