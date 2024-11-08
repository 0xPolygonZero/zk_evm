// Return the next context ID, and record the old context ID in the new one's
// @CTX_METADATA_PARENT_CONTEXT field. Does not actually enter the new context.
%macro create_context
    // stack: (empty)
    %next_context_id
    %set_new_ctx_parent_ctx
    // stack: new_ctx
%endmacro

// Get and increment @GLOBAL_METADATA_LARGEST_CONTEXT to determine the next context ID.
%macro next_context_id
    // stack: (empty)
    %mload_global_metadata(@GLOBAL_METADATA_LARGEST_CONTEXT)
    %add_const(0x10000000000000000) // scale each context by 2^64
    // stack: new_ctx
    DUP1

    // Memory addresses are represented as `ctx.2^64 + segment.2^32 + offset`,
    // each address component expected to fit in a 32-bit limb.
    // We enforce here that the new context id won't overflow.
    PUSH 0xffffffffffffffffffffffff // 2^96 - 1
    // stack: max, new_ctx, new_ctx
    LT
    %jumpi(fault_exception)

    // stack: new_ctx
    DUP1
    %mstore_global_metadata(@GLOBAL_METADATA_LARGEST_CONTEXT)
    // stack: new_ctx
%endmacro

// Returns whether the current transaction is a contract creation transaction.
%macro is_contract_creation
    // stack: (empty)
    %mload_global_metadata(@GLOBAL_METADATA_CONTRACT_CREATION)
%endmacro

%macro is_precompile
    // stack: addr
    DUP1 %ge_const(@ECREC)
    SWAP1
    // stack: addr, addr>=1
    #[cfg(feature = eth_mainnet)]
    {
        %le_const(@KZG_PEVAL)
        // stack: addr>=1, addr<=10
    }
    // TODO: Update after support of EIP-7712 for Polygon Pos, https://github.com/0xPolygonZero/zk_evm/issues/265
    #[cfg(not(feature = eth_mainnet))]
    {
        %le_const(@BLAKE2_F)
        // stack: addr>=1, addr<=9
    }
    MUL // Cheaper than AND
%endmacro

// Returns 1 if the account is non-existent, 0 otherwise.
%macro is_non_existent
    // stack: addr
    #[cfg(feature = eth_mainnet)]
    {
        %mpt_read_state_trie ISZERO
    }
    #[cfg(feature = cdk_erigon)]
    {
        %key_code %search_key ISZERO
    }
%endmacro


// Returns 1 if the account is empty, 0 otherwise.
%macro is_empty
    #[cfg(feature = eth_mainnet)]
    {
        // stack: addr
        %mpt_read_state_trie
        // stack: account_ptr
        DUP1 ISZERO 
    } 
    #[cfg(feature = cdk_erigon)]
    {
        // stack: addr
        DUP1 %read_nonce
        // stack: nonce, addr
        ISZERO %not_bit
    }   
    %jumpi(%%false)
    #[cfg(feature = eth_mainnet)]
    {
        // stack: account_ptr
        DUP1 %mload_trie_data
        // stack: nonce, account_ptr
        ISZERO %not_bit 
    }
     #[cfg(feature = cdk_erigon)]
    {
        // stack: addr
        DUP1 %read_nonce
        // stack: nonce, addr
        ISZERO %not_bit
    }  
    %jumpi(%%false)
    #[cfg(feature = eth_mainnet)]
    {
        %increment DUP1 %mload_trie_data
        // stack: balance, balance_ptr
        ISZERO %not_bit 
    }
     #[cfg(feature = cdk_erigon)]
    {
        // stack: addr
        DUP1 %read_balance
        // stack: balance, addr
        ISZERO %not_bit
    }  
    %jumpi(%%false)
    #[cfg(feature = eth_mainnet)]
    {
        %add_const(2) %mload_trie_data
        // stack: code_hash
        PUSH @EMPTY_STRING_KECCAK_HASH
        EQ
    }
     #[cfg(feature = cdk_erigon)]
    {
        // stack: addr
        %read_code
        // stack: codehash
        %eq_const(@EMPTY_STRING_POSEIDON_HASH)
    } 
    %jump(%%after)
%%false:
    // stack: account_ptr
    POP
    PUSH 0
%%after:
%endmacro

// Returns 1 if the account is dead (i.e., empty or non-existent), 0 otherwise.
%macro is_dead
    // stack: addr
    DUP1 %is_non_existent
    SWAP1 %is_empty
    ADD // OR
%endmacro

// Gets the size of the stack _before_ the macro is run
// WARNING: this macro is side-effecting. It writes the current stack length to offset
// `CTX_METADATA_STACK_SIZE`, segment `SEGMENT_CONTEXT_METADATA` in the current context. But I can't
// imagine it being an issue unless someone's doing something dumb.
%macro stack_length
    // stack: (empty)
    GET_CONTEXT
    // stack: current_ctx
    // It seems odd to switch to the context that we are already in. We do this because SET_CONTEXT
    // saves the stack length of the context we are leaving in its metadata segment.
    SET_CONTEXT
    // stack: (empty)
    // We can now read this stack length from memory.
    %mload_context_metadata(@CTX_METADATA_STACK_SIZE)
    // stack: stack_length
%endmacro

%macro set_and_prune_ctx
    // stack: context
    PUSH 1 ADD
    SET_CONTEXT
    // stack: (empty)
%endmacro

%macro mstore_u256_max
    // stack: addr
    PUSH @U256_MAX
    MSTORE_GENERAL
%endmacro

// Adds stale_ctx to the list of stale contexts. You need to return to a previous, older context with
// a SET_CONTEXT instruction. By assumption, stale_ctx is greater than the current context.
global prune_context:
    // stack: stale_ctx, retdest
    GET_CONTEXT
    // stack: curr_ctx, stale_ctx, retdest
    // When we go to stale_ctx, we want its stack to contain curr_ctx so that we can immediately
    // call SET_CONTEXT. For that, we need a stack length of 1, and store curr_ctx in Segment::Stack[0].
    PUSH @SEGMENT_STACK
    DUP3 ADD
    // stack: stale_ctx_stack_addr, curr_ctx, stale_ctx, retdest
    DUP2
    // stack: curr_ctx, stale_ctx_stack_addr, curr_ctx, stale_ctx, retdest
    MSTORE_GENERAL
    // stack: curr_ctx, stale_ctx, retdest
    PUSH @CTX_METADATA_STACK_SIZE
    DUP3 ADD
    // stack: stale_ctx_stack_size_addr, curr_ctx, stale_ctx, retdest
    PUSH 1
    MSTORE_GENERAL
    // stack: curr_ctx, stale_ctx, retdest
    POP
    SET_CONTEXT
    // We're now in stale_ctx, with stack: curr_ctx, retdest
    %set_and_prune_ctx
    // We're now in curr_ctx, with stack: retdest
    JUMP

%macro prune_context
    // stack: stale_ctx
    %stack (stale_ctx) -> (stale_ctx, %%after)
    %jump(prune_context)
%%after:
%endmacro
