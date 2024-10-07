global precompile_bn_add:
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

    %charge_gas_const(@BN_ADD_GAS)

    GET_CONTEXT
    PUSH @SEGMENT_CALLDATA
    %build_address_no_offset
    // stack: base_addr, kexit_info

    // Load x0, y0, x1, y1 from the call data using `MLOAD_32BYTES`.
    PUSH bn_add_return
    // stack: bn_add_return, base_addr, kexit_info
    %stack (bn_add_return, base_addr) -> (base_addr, 96, 32, bn_add_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: y1, bn_add_return, base_addr, kexit_info
    %stack (y1, bn_add_return, base_addr) -> (base_addr, 64, 32, y1, bn_add_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: x1, y1, bn_add_return, base_addr, kexit_info
    %stack (x1, y1, bn_add_return, base_addr) -> (base_addr, 32, 32, x1, y1, bn_add_return, base_addr)
    ADD // base_addr + offset
    MLOAD_32BYTES
    // stack: y0, x1, y1, bn_add_return, base_addr, kexit_info
    %stack (y0, x1, y1, bn_add_return, base_addr) -> (base_addr, 32, y0, x1, y1, bn_add_return, base_addr)
    MLOAD_32BYTES
    // stack: x0, y0, x1, y1, bn_add_return, base_addr, kexit_info
    %jump(bn_add)
bn_add_return:
    // stack: x, y, base_addr, kexit_info
    DUP2 %eq_const(@U256_MAX) // bn_add returns (U256_MAX, U256_MAX) on bad input.
    DUP2 %eq_const(@U256_MAX) // bn_add returns (U256_MAX, U256_MAX) on bad input.
    MUL // Cheaper than AND
    %jumpi(fault_exception)
    // stack: x, y, base_addr, kexit_info

    // Store the result (x, y) to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 64)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    %stack (parent_ctx, x, y) -> (parent_ctx, @SEGMENT_RETURNDATA, x, y)
    %build_address_no_offset
    // stack: addr_x, x, y, base_addr, kexit_info
    MSTORE_32BYTES_32
    // stack: addr_y = addr_x + 32, y, base_addr, kexit_info
    MSTORE_32BYTES_32
    // stack: addr, base_addr, kexit_info
    POP
    %jump(pop_and_return_success)
