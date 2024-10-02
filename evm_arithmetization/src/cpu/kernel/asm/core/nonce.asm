// Get the nonce of the given account.
// Pre stack: address, retdest
// Post stack: (empty)
global nonce:
    #[cfg(feature = eth_mainnet)]
    {
        // stack: address, retdest
        %mpt_read_state_trie
        // stack: account_ptr, retdest
        // The nonce is the first account field, so we deref the account pointer itself.
        // Note: We don't need to handle account_ptr=0, as trie_data[0] = 0,
        // so the deref will give 0 (the default nonce) as desired.
        %mload_trie_data
        // stack: nonce, retdest
        SWAP1 JUMP
    }
    #[cfg(feature = cdk_erigon)]
    {
        // stack: address, retdest
        %read_nonce %mload_trie_data
        // stack: nonce, retdest
        SWAP1 JUMP
    }

// Convenience macro to call nonce and return where we left off.
%macro nonce
    %stack (address) -> (address, %%after)
    %jump(nonce)
%%after:
%endmacro

// Increment the given account's nonce. Assumes the account already exists; panics otherwise.
global increment_nonce:
    #[cfg(feature = eth_mainnet)]
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
        // stack: nonce_ptr, address, retdest
        DUP1 ISZERO %jumpi(create_nonce)
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

        create_nonce:
            // stack: nonce_ptr, address, retdest
            POP
            // stack: address, retdest
            PUSH 0 DUP2 %journal_add_nonce_change
            // stack: address, retdest
            PUSH 1
            SWAP1
            %set_nonce
    }


// Convenience macro to call increment_nonce and return where we left off.
%macro increment_nonce
    %stack (address) -> (address, %%after)
    %jump(increment_nonce)
%%after:
%endmacro
