global precompile_kzg_peval:
    // stack: retdest, new_ctx, (old stack)
    POP
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

    %charge_gas_const(@KZG_PEVAL_GAS)

    // Load `versioned_hash | z | y | commitment | proof` from the call data using `MLOAD_32BYTES`.
    // Note that `z` and `y` are padded 32 byte big endian values, and `commitment` and `proof` are
    // both 48 bytes big-endian encoded values.
    // stack: kexit_info
    PUSH @SEGMENT_CALLDATA
    GET_CONTEXT
    %build_address_no_offset
    // stack: base_addr, kexit_info
    PUSH 16
    DUP2 %add_const(176)
    MLOAD_32BYTES
    // stack: proof_lo, base_addr, kexit_info
    PUSH 32
    DUP3 %add_const(144)
    MLOAD_32BYTES
    // stack: proof_hi, proof_lo, base_addr, kexit_info
    PUSH 16
    DUP4 %add_const(128)
    MLOAD_32BYTES
    // stack: comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    PUSH 32
    DUP5 %add_const(96)
    MLOAD_32BYTES
    // stack: comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    PUSH 32
    DUP6 %add_const(64)
    MLOAD_32BYTES
    // stack: y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    PUSH 32
    DUP7 %add_const(32)
    MLOAD_32BYTES
    // stack: z, y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    PUSH 32
    DUP8 // no offset
    MLOAD_32BYTES

global verify_kzg_proof:
    // stack: versioned_hash, z, y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    PROVER_INPUT(kzg_point_eval)
    DUP1 ISZERO
    // stack: is_invalid, res_hi, versioned_hash, z, y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    %jumpi(fault_exception)
    PROVER_INPUT(kzg_point_eval_2)
    // stack: res_lo, res_hi, versioned_hash, z, y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info
    %stack (res_lo, res_hi, versioned_hash, z, y, comm_hi, comm_lo, proof_hi, proof_lo, base_addr, kexit_info) ->
        (res_lo, res_hi, kexit_info)

global store_kzg_verification:
    // Store the result to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 64)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    // stack: parent_ctx, res_lo, res_hi, kexit_info
    PUSH @SEGMENT_RETURNDATA
    %build_address_no_offset
    // stack: addr, res_lo, res_hi, kexit_info
    MSTORE_32BYTES_32
    // stack: addr', res_hi, kexit_info
    MSTORE_32BYTES_32
    // stack: kexit_info

    POP
    %leftover_gas
    // stack: leftover_gas
    PUSH 1 // success
    %jump(terminate_common)

    SWAP1
