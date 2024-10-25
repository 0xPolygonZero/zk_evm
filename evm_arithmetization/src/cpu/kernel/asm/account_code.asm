global sys_extcodehash:
    // stack: kexit_info, address
    SWAP1 %u256_to_addr
    // stack: address, kexit_info
    SWAP1
    DUP2 %insert_accessed_addresses
    // stack: cold_access, kexit_info, address
    PUSH @GAS_COLDACCOUNTACCESS_MINUS_WARMACCESS
    MUL
    PUSH @GAS_WARMACCESS
    ADD
    %charge_gas
    // stack: kexit_info, address

    SWAP1
    DUP1 %is_dead %jumpi(extcodehash_dead)
    %extcodehash
    // stack: hash, kexit_info
    SWAP1
    EXIT_KERNEL
extcodehash_dead:
    %stack (address, kexit_info) -> (kexit_info, 0)
    EXIT_KERNEL

#[cfg(feature = eth_mainnet)]
{
global extcodehash:
        // stack: address, retdest
        %mpt_read_state_trie
        // stack: account_ptr, retdest
        DUP1 ISZERO %jumpi(retzero)
        %add_const(3)
        // stack: codehash_ptr, retdest
        %mload_trie_data
        // stack: codehash, retdest
        SWAP1 JUMP
    retzero:
        %stack (account_ptr, retdest) -> (retdest, 0)
        JUMP
}
#[cfg(feature = cdk_erigon)]
{
global extcodehash:
    // stack: address, retdest
    %read_code
    // stack: codehash, retdest
    SWAP1 JUMP
}

%macro extcodehash
    %stack (address) -> (address, %%after)
    %jump(extcodehash)
%%after:
%endmacro

#[cfg(feature = eth_mainnet)]
{
    %macro ext_code_empty
    %extcodehash
    %eq_const(@EMPTY_STRING_HASH)
%endmacro
}
#[cfg(feature = cdk_erigon)]
{
    %macro ext_code_empty
        %extcodehash
        %eq_const(@EMPTY_STRING_POSEIDON_HASH)
    %endmacro
}

%macro extcodesize
    %stack (address) -> (address, %%after)
    %jump(extcodesize)
%%after:
%endmacro

global sys_extcodesize:
    // stack: kexit_info, address
    SWAP1 %u256_to_addr
    // stack: address, kexit_info
    SWAP1
    DUP2 %insert_accessed_addresses
    // stack: cold_access, kexit_info, address
    PUSH @GAS_COLDACCOUNTACCESS_MINUS_WARMACCESS
    MUL
    PUSH @GAS_WARMACCESS
    ADD
    %charge_gas
    // stack: kexit_info, address

    SWAP1
    // stack: address, kexit_info
    %extcodesize
    // stack: code_size, codesize_ctx, kexit_info
    SWAP1
    // stack: codesize_ctx, code_size, kexit_info
    %prune_context
    // stack: code_size, kexit_info
    SWAP1
    EXIT_KERNEL

// Pre stack: address, retdest
// Post stack: code_size, codesize_ctx
global extcodesize:
    // stack: address, retdest
    %next_context_id
    %stack(codesize_ctx, address, retdest) -> (address, codesize_ctx, retdest, codesize_ctx)
    %jump(load_code)

// Loads the code at `address` into memory, in the code segment of the given context, starting at offset 0.
// Checks that the hash of the loaded code corresponds to the `codehash` in the state trie.
// Pre stack: address, ctx, retdest
// Post stack: code_size
//
// NOTE: The provided `dest` **MUST** have a virtual address of 0.
global load_code:
    %stack (address, ctx, retdest) -> (extcodehash, address, load_code_ctd, ctx, retdest)
    JUMP
load_code_ctd:
    // stack: codehash, ctx, retdest
    DUP1 ISZERO %jumpi(load_code_non_existent_account)
    // Load the code non-deterministically in memory and return the length.
global debug_account_code:
    PROVER_INPUT(account_code)
#[cfg(feature = eth_mainnet)]
{
    %stack (code_size, codehash, ctx, retdest) -> (ctx, code_size, codehash, retdest, code_size)
    // Check that the hash of the loaded code equals `codehash`.
    // ctx == DST, as SEGMENT_CODE == offset == 0.
    KECCAK_GENERAL
    // stack: shouldbecodehash, codehash, retdest, code_size
    %assert_eq
    // stack: retdest, code_size
    JUMP
}
#[cfg(feature = cdk_erigon)]
{
    %jump(poseidon_hash_code)
}

load_code_non_existent_account:
    // Write 0 at address 0 for soundness: SEGMENT_CODE == 0, hence ctx == addr.
    // stack: codehash, addr, retdest
    %stack (codehash, addr, retdest) -> (0, addr, retdest, 0)
    MSTORE_GENERAL
    // stack: retdest, 0
    JUMP

// Identical to load_code, but adds 33 zeros after code_size for soundness reasons.
// If the code ends with an incomplete PUSH, we must make sure that every subsequent read is 0,
// accordingly to the Ethereum specs.
// Pre stack: address, ctx, retdest
// Post stack: code_size
global load_code_padded:
    %stack (address, ctx, retdest) -> (address, ctx, load_code_padded_ctd, ctx, retdest)
    %jump(load_code)

load_code_padded_ctd:
    // SEGMENT_CODE == 0.
    // stack: code_size, ctx, retdest
    %stack (code_size, ctx, retdest) -> (ctx, code_size, 0, retdest, code_size)
    ADD 
    // stack: addr, 0, retdest, code_size
    MSTORE_32BYTES_32
    // stack: addr', retdest, code_size
    PUSH 0
    MSTORE_GENERAL
    // stack: retdest, code_size
    JUMP

#[cfg(feature = cdk_erigon)]
{
    global poseidon_hash_code:
    // stack: padded_code_size, codehash, ctx, retdest
    // %stack (padded_code_size, codehash, ctx) -> (0, 0, padded_code_size, ctx, codehash)
    %stack (padded_code_size, codehash, ctx) -> (ctx, padded_code_size, codehash, padded_code_size, ctx)
    POSEIDON_GENERAL
    %assert_eq
    // stack: padded_code_size, ctx, retdest
    %decrement
    remove_padding_loop:
        // stack: offset, ctx, retdest
        DUP2 DUP2 ADD DUP1 MLOAD_GENERAL
        // stack: code[offset], offset+ctx, offset, ctx, retdest
        SWAP1 PUSH 0 MSTORE_GENERAL
        // stack: code[offset], offset, ctx, retdest
        %and_const(1) %jumpi(remove_padding_after)
        // stack: offset, ctx, retdest
        %decrement %jump(remove_padding_loop)

    remove_padding_after:
        %stack (offset, ctx, retdest) -> (retdest, offset)
        JUMP

    // Convenience macro to call poseidon_hash_code_unpadded and return where we left off.
    %macro poseidon_hash_code_unpadded
        %stack (addr, len) -> (addr, len, %%after)
        %jump(poseidon_hash_code_unpadded)
    %%after:
    %endmacro

    /// Applies the padding rule to the code located at the provided address before hashing it.
    /// Memory cells after the last code byte will be overwritten.
    global poseidon_hash_code_unpadded:
        // stack: addr, len, retdest
        DUP2 ISZERO %jumpi(poseidon_empty_code)
        DUP2 DUP2 ADD
        // stack: padding_addr, addr, len, retdest

        // write 1 after the last code byte
        DUP1 PUSH 1 MSTORE_GENERAL
        // stack: padding_addr, addr, len, retdest
        %increment
        // stack: padding_addr, addr, len, retdest

        // Pad with 0s until the length is a multiple of 56
        PUSH 56
        DUP4 %increment
    global debug_len_p_one:
        // stack: curr_len, 56, padding_addr, addr, len, retdest
        PUSH 56 SWAP1 SUB
        // stack: curr_len - 56, 56, padding_addr, addr, len, retdest
        MOD
    global debug_to_padd:
        // stack: padding_len, padding_addr, addr, len, retdest
        SWAP3 DUP4
        // stack: padding_len, len, padding_addr, addr, padding_len, retdest
        ADD
        // stack: last_byte_offset, padding_addr, addr, padding_len, retdest
        %stack (last_byte_offset, padding_addr, addr, padding_len)
            -> (padding_addr, padding_len, after_padding, addr, last_byte_offset)
        %jump(memset)
    after_padding:
        // stack: addr, last_byte_offset, retdest

        // Xor the last element with 0x80
        PUSH 1 DUP3 ADD
        // stack: total_code_len, addr, last_byte_offset, retdest
        SWAP2
        // stack: last_byte_offset, addr, total_code_len, retdest
        DUP2 ADD
        // stack: last_byte_addr, addr, total_code_len, retdest
        DUP1 MLOAD_GENERAL
        // stack: last_byte, last_byte_addr, addr, total_code_len, retdest
        PUSH 0x80 ADD
        // stack: last_byte_updated, last_byte_addr, addr, total_code_len, retdest
        MSTORE_GENERAL
        // stack: addr, total_code_len, retdest

        POSEIDON_GENERAL
        // stack: codehash, retdest
        SWAP1
        JUMP

    global poseidon_empty_code:
        // stack: addr, len, retdest
        %stack (addr, len, retdest) -> (retdest, @EMPTY_STRING_POSEIDON_HASH)
        JUMP

}
