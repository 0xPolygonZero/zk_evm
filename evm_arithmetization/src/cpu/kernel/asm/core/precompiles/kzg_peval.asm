global precompile_kzg_peval:
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
    PUSH 0x100000000 // = 2^32 (is_kernel = true)
    // stack: kexit_info

    %charge_gas_const(@BN_ADD_GAS)

    // Load `versioned_hash | z | y | commitment | proof` from the call data using `MLOAD_32BYTES`.
    // Note that `z` and `y` are padded 32 byte big endian values, and `commitment` and `proof` are
    // both 48 bytes values.
    // stack: kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 176, 16)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 176, 16, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 144, 32)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 144, 32, proof_hi, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: proof_lo, proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 128, 16)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 128, 16, proof_lo, proof_hi, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: comm_hi, proof_lo, proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 96, 32)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 96, 32, comm_hi, proof_lo, proof_hi, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 64, 32)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 64, 32, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 32, 32)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 32, 32, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %build_address
    MLOAD_32BYTES
    // stack: z, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %stack () -> (@SEGMENT_CALLDATA, 32)
    GET_CONTEXT
    // stack: ctx, @SEGMENT_CALLDATA, 32, z, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %build_address_no_offset
    MLOAD_32BYTES

global verify_kzg_proof:
    // stack: versioned_hash, z, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    PROVER_INPUT(kzg_point_eval)
    // stack: result, versioned_hash, z, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info
    %stack (result, versioned_hash, z, y, comm_lo, comm_hi, proof_lo, proof_hi, kexit_info) ->
        (result, kexit_info)

    // Store the result to the parent's return data using `mstore_unpacking`.
    %mstore_parent_context_metadata(@CTX_METADATA_RETURNDATA_SIZE, 32)
    %mload_context_metadata(@CTX_METADATA_PARENT_CONTEXT)
    %stack (parent_ctx, result) -> (parent_ctx, @SEGMENT_RETURNDATA, result, result)
    %build_address_no_offset
    MSTORE_32BYTES_32
    // stack: result, kexit_info

    POP
    %leftover_gas
    // stack: leftover_gas
    PUSH 1 // success
    %jump(terminate_common)

    SWAP1
