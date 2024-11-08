// Get the nonce of the given account.
// Pre stack: address, retdest
// Post stack: (empty)
global nonce:
    // stack: address, retdest
    %read_nonce
    // stack: nonce, retdest
    SWAP1 JUMP

// Convenience macro to call nonce and return where we left off.
%macro nonce
    %stack (address) -> (address, %%after)
    %jump(nonce)
%%after:
%endmacro

// Increment the given account's nonce. Assumes the account already exists; panics otherwise.
global increment_nonce:
    #[cfg(not(feature = cdk_erigon))]
    {
        // stack: address, retdest
        DUP1
        %mpt_read_state_trie
        // stack: account_ptr, address, retdest
        DUP1 ISZERO %jumpi(increment_nonce_no_such_account)
        // stack: nonce_ptr, address, retdest
        DUP1 %mload_trie_data
        // stack: nonce, nonce_ptr, address, retdest
        DUP1 DUP4 %journal_add_nonce_change
        // stack: nonce, nonce_ptr, address, retdest
        %increment
        SWAP1
        // stack: nonce_ptr, nonce', address, retdest
        %mstore_trie_data
        // stack: address, retdest
        POP
        JUMP
    global increment_nonce_no_such_account:
        PANIC
    }
    #[cfg(feature = cdk_erigon)]
    {
        // stack: address, retdest
        DUP1
        %read_nonce
        // stack: nonce, address, retdest
        DUP1 ISZERO %jumpi(create_nonce)
        // stack: nonce, address, retdest
        // stack: nonce, address, retdest
        DUP1 DUP3 %journal_add_nonce_change
        // stack: nonce, address, retdest
        %increment
        SWAP1
        // stack: address, nonce', retdest
        %set_nonce
        // stack: retdest
        JUMP

        create_nonce:
            // stack: nonce, address, retdest
            POP
            // stack: address, retdest
            PUSH 0 DUP2 %journal_add_nonce_change
            // stack: address, retdest
            PUSH 1
            SWAP1
            %set_nonce
            JUMP
    }


// Convenience macro to call increment_nonce and return where we left off.
%macro increment_nonce
    %stack (address) -> (address, %%after)
    %jump(increment_nonce)
%%after:
%endmacro
