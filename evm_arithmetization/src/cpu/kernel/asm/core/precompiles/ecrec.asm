global precompile_ecrec:
    // stack: address, retdest, new_ctx, (old stack)
    %pop2
    // stack: new_ctx, (old stack)
    %set_new_ctx_parent_pc(after_precompile)
    // stack: new_ctx, (old stack)
    DUP1
    SET_CONTEXT
    %checkpoint // Checkpoint
    %increment_call_depth
    // stack: (empty)
    PUSH @IS_KERNEL // true
    // stack: kexit_info

    %charge_gas_const(@ECREC_GAS)

    GET_CONTEXT
    PUSH @SEGMENT_CALLDATA
    %build_address_no_offset
    // stack: base_addr, kexit_info

    // Load hash, v, r, s from the call data using `MLOAD_32BYTES`.
    PUSH ecrec_return
    // stack: ecrec_return, base_addr, kexit_info

    %stack (ecrec_return, base_addr) -> (base_addr, 96, 32, ecrec_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: s, ecrec_return, base_addr, kexit_info
    %stack (s, ecrec_return, base_addr) -> (base_addr, 64, 32, s, ecrec_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: r, s, ecrec_return, base_addr, kexit_info
    %stack (r, s, ecrec_return, base_addr) -> (base_addr, 32, 32, r, s, ecrec_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: v, r, s, ecrec_return, base_addr, kexit_info
    %stack (v, r, s, ecrec_return, base_addr) -> (base_addr, 32, v, r, s, ecrec_return, base_addr)
    MLOAD_32BYTES
    // stack: hash, v, r, s, ecrec_return, base_addr, kexit_info
    %jump(ecrecover)
ecrec_return:
    // stack: address, base_addr, kexit_info
    DUP1 %eq_const(@U256_MAX) %jumpi(ecrec_bad_input) // ecrecover returns U256_MAX on bad input.

    // Store the result address to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 32)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    %stack (parent_ctx, address) -> (parent_ctx, @SEGMENT_RETURNDATA, address)
    %build_address_no_offset
    MSTORE_32BYTES_32
    // stack: addr, base_addr, kexit_info
    POP
    %jump(pop_and_return_success)

// On bad input, return empty return data but still return success.
ecrec_bad_input:
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 0)
    // stack: addr, base_addr, kexit_info
    POP
    %jump(pop_and_return_success)
