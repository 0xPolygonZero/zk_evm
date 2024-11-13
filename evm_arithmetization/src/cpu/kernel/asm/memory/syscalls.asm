global sys_mload:
    // stack: kexit_info, offset
    DUP2 %ensure_reasonable_offset
    // stack: kexit_info, offset
    %charge_gas_const(@GAS_VERYLOW)
    // stack: kexit_info, offset
    DUP2 %add_const(32)
    // stack: expanded_num_bytes, kexit_info, offset
    %update_mem_bytes
    // stack: kexit_info, offset
    %stack(kexit_info, offset) -> (offset, 32, kexit_info)
    PUSH @SEGMENT_MAIN_MEMORY
    GET_CONTEXT
    %build_address
    // stack: addr, len, kexit_info
    MLOAD_32BYTES
    %stack (value, kexit_info) -> (kexit_info, value)
    EXIT_KERNEL

global sys_mstore:
    // stack: kexit_info, offset, value
    DUP2 %ensure_reasonable_offset
    // stack: kexit_info, offset, value
    %charge_gas_const(@GAS_VERYLOW)
    // stack: kexit_info, offset, value
    DUP2 %add_const(32)
    // stack: expanded_num_bytes, kexit_info, offset, value
    %update_mem_bytes
    // stack: kexit_info, offset, value
    %stack(kexit_info, offset, value) -> (offset, value, kexit_info)
    PUSH @SEGMENT_MAIN_MEMORY
    GET_CONTEXT
    %build_address
    // stack: addr, value, kexit_info
    MSTORE_32BYTES_32
    POP
    // stack: kexit_info
    EXIT_KERNEL

global sys_mstore8:
    // stack: kexit_info, offset, value
    DUP2 %ensure_reasonable_offset
    // stack: kexit_info, offset, value
    %charge_gas_const(@GAS_VERYLOW)
    // stack: kexit_info, offset, value
    DUP2 INCR1
    // stack: expanded_num_bytes, kexit_info, offset, value
    %update_mem_bytes
    // stack: kexit_info, offset, value
    %stack (kexit_info, offset, value) -> (value, 0x100, offset, kexit_info)
    MOD SWAP1
    %mstore_current(@SEGMENT_MAIN_MEMORY)
    // stack: kexit_info
    EXIT_KERNEL

global sys_calldataload:
    // stack: kexit_info, i
    %charge_gas_const(@GAS_VERYLOW)
    // stack: kexit_info, i
    %mload_context_metadata(@CTX_METADATA_CALLDATA_SIZE)
    %stack (calldata_size, kexit_info, i) -> (calldata_size, i, kexit_info, i)
    LT %jumpi(calldataload_large_offset)
    %stack (kexit_info, i) -> (@SEGMENT_CALLDATA, i, 32, kexit_info)
    GET_CONTEXT
    %build_address
    // stack: addr, 32, kexit_info
    MLOAD_32BYTES
sys_calldataload_after_mload_packing:
    // stack: value, kexit_info
    SWAP1
    EXIT_KERNEL
    PANIC
calldataload_large_offset:
    %stack (kexit_info, i) -> (kexit_info, 0)
    EXIT_KERNEL

// Macro for {CALLDATA, RETURNDATA}COPY (W_copy in Yellow Paper).
%macro wcopy(segment, context_metadata_size)
    // stack: kexit_info, dest_offset, offset, size
    %wcopy_charge_gas

    %stack (kexit_info, dest_offset, offset, size) ->
        (dest_offset, size, kexit_info, dest_offset, offset, size)
    %add_or_fault
    // stack: expanded_num_bytes, kexit_info, dest_offset, offset, size, kexit_info
    DUP1 %ensure_reasonable_offset
    %update_mem_bytes

    %mload_context_metadata($context_metadata_size)
    // stack: total_size, kexit_info, dest_offset, offset, size
    DUP4
    // stack: offset, total_size, kexit_info, dest_offset, offset, size
    GT %jumpi(wcopy_large_offset)

    // stack: kexit_info, dest_offset, offset, size
    // Ensure that `offset + size` won't overflow the reserved 32-bit limb
    // of the `virtual` component of the source memory address.
    DUP4 DUP4
    // stack: offset, size, kexit_info, dest_offset, offset, size
    %check_u32_add

    // stack: kexit_info, dest_offset, offset, size
    GET_CONTEXT
    PUSH $segment
    %build_address_no_offset
    // stack: base_addr, kexit_info, dest_offset, offset, size
    %jump(wcopy_within_bounds)
%endmacro

%macro wcopy_charge_gas
    // stack: kexit_info, dest_offset, offset, size
    PUSH @GAS_VERYLOW
    DUP5
    // stack: size, Gverylow, kexit_info, dest_offset, offset, size
    ISZERO %jumpi(wcopy_empty)
    // stack: Gverylow, kexit_info, dest_offset, offset, size
    DUP5 %num_bytes_to_num_words %mul_const(@GAS_COPY) ADD %charge_gas
%endmacro


codecopy_within_bounds:
    // stack: total_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    POP
    // stack: segment, src_ctx, kexit_info, dest_offset, offset, size
    GET_CONTEXT
    %stack (context, segment, src_ctx, kexit_info, dest_offset, offset, size) ->
        (src_ctx, segment, offset, @SEGMENT_MAIN_MEMORY, dest_offset, context, size, codecopy_after, src_ctx, kexit_info)
    %build_address
    SWAP3 %build_address
    // stack: DST, SRC, size, codecopy_after, src_ctx, kexit_info
    %jump(memcpy_bytes)

wcopy_within_bounds:
    // stack: base_addr, kexit_info, dest_offset, offset, size
    GET_CONTEXT
    %stack (context, base_addr, kexit_info, dest_offset, offset, size) ->
        (base_addr, offset, @SEGMENT_MAIN_MEMORY, dest_offset, context, size, wcopy_after, kexit_info)
    ADD // SRC
    SWAP3 %build_address
    // stack: DST, SRC, size, wcopy_after, kexit_info
    %jump(memcpy_bytes)

wcopy_empty:
    // stack: Gverylow, kexit_info, dest_offset, offset, size
    %charge_gas
    %stack (kexit_info, dest_offset, offset, size) -> (kexit_info)
    EXIT_KERNEL


codecopy_large_offset:
    // stack: total_size, src_ctx, kexit_info, dest_offset, offset, size
    POP
    // offset is larger than the size of the {CALLDATA,CODE,RETURNDATA}. So we just have to write zeros.
    // stack: src_ctx, kexit_info, dest_offset, offset, size
    GET_CONTEXT
    %stack (context, src_ctx, kexit_info, dest_offset, offset, size) ->
        (context, @SEGMENT_MAIN_MEMORY, dest_offset, size, codecopy_after, src_ctx, kexit_info)
    %build_address
    %jump(memset)

wcopy_large_offset:
    // offset is larger than the size of the {CALLDATA,CODE,RETURNDATA}. So we just have to write zeros.
    // stack: kexit_info, dest_offset, offset, size
    GET_CONTEXT
    %stack (context, kexit_info, dest_offset, offset, size) ->
        (context, @SEGMENT_MAIN_MEMORY, dest_offset, size, wcopy_after, kexit_info)
    %build_address
    %jump(memset)

codecopy_after:
    // stack: src_ctx, kexit_info
    DUP1 GET_CONTEXT
    // stack: ctx, src_ctx, src_ctx, kexit_info
    // If ctx == src_ctx, it's a CODECOPY, and we don't need to prune the context.
    EQ
    // stack: ctx == src_ctx, src_ctx, kexit_info
    %jumpi(codecopy_no_prune)
    // stack: src_ctx, kexit_info
    %prune_context
    // stack: kexit_info
    EXIT_KERNEL

codecopy_no_prune:
    // stack: src_ctx, kexit_info
    POP
    EXIT_KERNEL

wcopy_after:
    // stack: kexit_info
    EXIT_KERNEL

// Pre stack: kexit_info, dest_offset, offset, size
// Post stack: (empty)
global sys_calldatacopy:
    %wcopy(@SEGMENT_CALLDATA, @CTX_METADATA_CALLDATA_SIZE)

// Pre stack: kexit_info, dest_offset, offset, size
// Post stack: (empty)
global sys_returndatacopy:
    DUP4 DUP4 %add_or_fault // Overflow check
    %mload_context_metadata(@CTX_METADATA_RETURNDATA_SIZE) LT %jumpi(fault_exception) // Data len check

    %wcopy(@SEGMENT_RETURNDATA, @CTX_METADATA_RETURNDATA_SIZE)

// Pre stack: kexit_info, dest_offset, offset, size
// Post stack: (empty)
global sys_codecopy:
    // stack: kexit_info, dest_offset, offset, size
    %wcopy_charge_gas

    %stack (kexit_info, dest_offset, offset, size) -> (dest_offset, size, kexit_info, dest_offset, offset, size)
    %add_or_fault
    // stack: expanded_num_bytes, kexit_info, dest_offset, offset, size, kexit_info
    DUP1 %ensure_reasonable_offset
    %update_mem_bytes

    GET_CONTEXT
    %mload_context_metadata(@CTX_METADATA_CODE_SIZE)
    // stack: code_size, ctx, kexit_info, dest_offset, offset, size
    %codecopy_after_checks(@SEGMENT_CODE)


// Pre stack: kexit_info, address, dest_offset, offset, size
// Post stack: (empty)
global sys_extcodecopy:
    %stack (kexit_info, address, dest_offset, offset, size)
        -> (address, dest_offset, offset, size, kexit_info)
    %u256_to_addr DUP1 %insert_accessed_addresses
    // stack: cold_access, address, dest_offset, offset, size, kexit_info
    PUSH @GAS_COLDACCOUNTACCESS_MINUS_WARMACCESS
    MUL
    PUSH @GAS_WARMACCESS
    ADD
    // stack: Gaccess, address, dest_offset, offset, size, kexit_info

    DUP5
    // stack: size, Gaccess, address, dest_offset, offset, size, kexit_info
    ISZERO %jumpi(sys_extcodecopy_empty)

    // stack: Gaccess, address, dest_offset, offset, size, kexit_info
    DUP5 %num_bytes_to_num_words %mul_const(@GAS_COPY) ADD
    %stack (gas, address, dest_offset, offset, size, kexit_info) -> (gas, kexit_info, address, dest_offset, offset, size)
    %charge_gas

    %stack (kexit_info, address, dest_offset, offset, size) -> (dest_offset, size, kexit_info, address, dest_offset, offset, size)
    %add_or_fault
    // stack: expanded_num_bytes, kexit_info, address, dest_offset, offset, size
    DUP1 %ensure_reasonable_offset
    %update_mem_bytes

    %next_context_id

    %stack (ctx, kexit_info, address, dest_offset, offset, size) ->
        (address, ctx, extcodecopy_contd, ctx, kexit_info, dest_offset, offset, size)
    %jump(load_code)

sys_extcodecopy_empty:
    %stack (Gaccess, address, dest_offset, offset, size, kexit_info) -> (Gaccess, kexit_info)
    %charge_gas
    EXIT_KERNEL

extcodecopy_contd:
    // stack: code_size, ctx, kexit_info, dest_offset, offset, size
    %codecopy_after_checks(@SEGMENT_CODE)

// Same as %wcopy but with special handling in case of overlapping ranges.
global sys_mcopy:
    // stack: kexit_info, dest_offset, offset, size
    %wcopy_charge_gas

    %stack (kexit_info, dest_offset, offset, size) -> (dest_offset, size, kexit_info, dest_offset, offset, size)
    %add_or_fault
    // stack: expanded_num_bytes, kexit_info, dest_offset, offset, size, kexit_info
    DUP1 %ensure_reasonable_offset
    %update_mem_bytes

    %stack (kexit_info, dest_offset, offset, size) -> (offset, size, kexit_info, dest_offset, offset, size)
    %add_or_fault
    DUP1 %ensure_reasonable_offset
    %update_mem_bytes

    // stack: kexit_info, dest_offset, offset, size
    DUP3 DUP3 EQ
    // stack: dest_offset = offset, kexit_info, dest_offset, offset, size
    %jumpi(mcopy_empty) // If SRC == DST, just pop the stack and exit the kernel

    // stack: kexit_info, dest_offset, offset, size
    GET_CONTEXT
    PUSH @SEGMENT_MAIN_MEMORY
    %build_address_no_offset

    DUP4 DUP4 LT
    // stack: dest_offset < offset, base_addr, kexit_info, dest_offset, offset, size
    %jumpi(wcopy_within_bounds)

    // stack: base_addr, kexit_info, dest_offset, offset, size

    DUP5 PUSH 32 %min
    // stack: shift=min(size, 32), base_addr, kexit_info, dest_offset, offset, size
    DUP5 DUP7 ADD
    // stack: offset + size, shift, base_addr, kexit_info, dest_offset, offset, size
    DUP5 LT
    // stack: dest_offset < offset + size, shift, base_addr, kexit_info, dest_offset, offset, size
    DUP2
    // stack: shift, dest_offset < offset + size, shift, base_addr, kexit_info, dest_offset, offset, size
    DUP8 GT
    // stack: size > shift, dest_offset < offset + size, shift, base_addr, kexit_info, dest_offset, offset, size
    MUL // AND
    // stack: (size > shift) && (dest_offset < offset + size), shift, base_addr, kexit_info, dest_offset, offset, size

    // If the conditions `size > shift` and `dest_offset < offset + size` are satisfied, that means
    // we will get an overlap that will overwrite some SRC data. In that case, we will proceed to the
    // memcpy in the backwards direction to never overwrite the SRC section before it has been read.
    %jumpi(mcopy_with_overlap)

    // Otherwise, we either have `SRC` < `DST`, or a small enough `size` that a single loop of
    // `memcpy_bytes` suffices and does not risk to overwrite `SRC` data before being read.
    // stack: shift, base_addr, kexit_info, dest_offset, offset, size
    POP
    %jump(wcopy_within_bounds)

mcopy_with_overlap:
    // We do have an overlap between the SRC and DST ranges.
    // We will proceed to `memcpy` in the backwards direction to prevent overwriting unread SRC data.
    // For this, we need to update `offset` and `dest_offset` to their final position, corresponding
    // to `x + size - min(32, size)`.

    // stack: shift=min(size, 32), base_addr, kexit_info, dest_offset, offset, size
    DUP1
    // stack: shift, shift, base_addr, kexit_info, dest_offset, offset, size
    DUP7 DUP7 ADD
    // stack: offset+size, shift, shift, base_addr, kexit_info, dest_offset, offset, size
    SUB
    // stack: offset'=offset+size-shift, shift, base_addr, kexit_info, dest_offset, offset, size
    SWAP4 DUP7 ADD
    // stack: dest_offset+size, shift, base_addr, kexit_info, offset', offset, size
    SUB
    // stack: dest_offset'=dest_offset+size-shift, base_addr, kexit_info, offset', offset, size

    DUP2 ADD // DST
    // stack: DST, base_addr, kexit_info, new_offset, offset, size
    SWAP3 ADD // SRC
    %stack (SRC, kexit_info, DST, offset, size) -> (DST, SRC, size, wcopy_after, kexit_info)
    %jump(memcpy_bytes_backwards)

mcopy_empty:
    // kexit_info, dest_offset, offset, size
    %stack (kexit_info, dest_offset, offset, size) -> (kexit_info)
    EXIT_KERNEL


// The internal logic is similar to wcopy, but handles range overflow differently.
// It is used for both CODECOPY and EXTCODECOPY.
%macro codecopy_after_checks(segment)
    // stack: total_size, src_ctx, kexit_info, dest_offset, offset, size
    DUP1 DUP6
    // stack: offset, total_size, total_size, src_ctx, kexit_info, dest_offset, offset, size
    GT %jumpi(codecopy_large_offset)

    PUSH $segment SWAP1
    // stack: total_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    DUP1 DUP8 DUP8 %add_or_fault
    // stack: offset + size, total_size, total_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    LT %jumpi(codecopy_within_bounds)

    // stack: total_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    DUP7 DUP7 ADD // We already checked for overflow.
    // stack: offset + size, total_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    SUB // extra_size = offset + size - total_size
    // stack: extra_size, segment, src_ctx, kexit_info, dest_offset, offset, size
    DUP1 DUP8 SUB
    // stack: copy_size = size - extra_size, extra_size, segment, src_ctx, kexit_info, dest_offset, offset, size

    // Compute the new dest_offset after actual copies, at which we will start padding with zeroes.
    DUP1 DUP7 ADD // We already checked for overflow.
    // stack: new_dest_offset, copy_size, extra_size, segment, src_ctx, kexit_info, dest_offset, offset, size

    GET_CONTEXT

    // The following 4-lines block is the inlined version of
    // %stack (context, new_dest_offset, copy_size, extra_size, segment, src_ctx, kexit_info, dest_offset, offset, size) ->
    //        (src_ctx, segment, offset, @SEGMENT_MAIN_MEMORY, dest_offset, context, copy_size, codecopy_large_offset, copy_size, src_ctx, kexit_info, new_dest_offset, offset, extra_size)
    PUSH codecopy_large_offset
    SWAP4 SWAP10 POP SWAP1 SWAP7
    PUSH @SEGMENT_MAIN_MEMORY
    DUP10 DUP5 SWAP7 DUP9

    %build_address
    SWAP3 %build_address
    // stack: DST, SRC, copy_size, codecopy_large_offset, copy_size, src_ctx, kexit_info, new_dest_offset, offset, extra_size
    %jump(memcpy_bytes)
%endmacro

