global precompile_bn_mul:
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

    %charge_gas_const(@BN_MUL_GAS)

    GET_CONTEXT
    PUSH @SEGMENT_CALLDATA
    %build_address_no_offset
    // stack: base_addr, kexit_info

    // Load x, y, n from the call data using `MLOAD_32BYTES`.
    PUSH bn_mul_return
    // stack: bn_mul_return, base_addr, kexit_info
    %stack (bn_mul_return, base_addr) -> (base_addr, 64, 32, bn_mul_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: n, bn_mul_return, base_addr, kexit_info
    %stack (n, bn_mul_return, base_addr) -> (base_addr, 32, 32, n, bn_mul_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: y, n, bn_mul_return, base_addr, kexit_info
    %stack (y, n, bn_mul_return, base_addr) -> (base_addr, 32, y, n, bn_mul_return, base_addr)
    MLOAD_32BYTES
    // stack: x, y, n, bn_mul_return, base_addr, kexit_info
    %jump(bn_mul)
bn_mul_return:
    // stack: Px, Py, base_addr, kexit_info
    DUP2 %eq_const(@U256_MAX) // bn_mul returns (U256_MAX, U256_MAX) on bad input.
    DUP2 %eq_const(@U256_MAX) // bn_mul returns (U256_MAX, U256_MAX) on bad input.
    MUL // Cheaper than AND
    %jumpi(fault_exception)
    // stack: Px, Py, kexit_info

    // Store the result (Px, Py) to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 64)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    %stack (parent_ctx, Px, Py) -> (parent_ctx, @SEGMENT_RETURNDATA, Px, parent_ctx, Py)
    %build_address_no_offset
    MSTORE_32BYTES_32
bn_mul_contd6:
    POP
    %stack (parent_ctx, Py) -> (parent_ctx, @SEGMENT_RETURNDATA, 32, Py)
    %build_address
    MSTORE_32BYTES_32
    // stack: addr, base_addr, kexit_info
    POP
    %jump(pop_and_return_success)
