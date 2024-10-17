// Type 3 transactions, introduced by EIP 4844, have the format
//     0x03 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value,
//                  data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s])
//
// The signed data is
//     keccak256(0x03 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
//                       to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes]))

global process_type_3_txn:
    // stack: rlp_addr, retdest
    // Store txn type.
    PUSH 3
    %mstore_txn_field(@TXN_FIELD_TYPE)

    // stack: rlp_addr, retdest
    // Initial rlp address offset of 1 (skipping over the 0x03 byte)
    %add_const(1)
    // stack: rlp_addr, retdest
    %decode_rlp_list_len
    // We don't actually need the length.
    %stack (rlp_addr, len) -> (rlp_addr)

    // stack: rlp_addr, retdest
    %store_chain_id_present_true
    // stack: rlp_addr, retdest
    // Keep track of the chain id position.
    DUP1
    // stack: rlp_addr, chain_id_addr, retdest
    %decode_and_store_chain_id
    %decode_and_store_nonce
    %decode_and_store_max_priority_fee
    %decode_and_store_max_fee
    %decode_and_store_gas_limit
    %decode_and_store_to
    %decode_and_store_value
    %decode_and_store_data
    %decode_and_store_access_list
    %decode_and_store_max_fee_per_blob_gas
    %decode_and_store_blob_versioned_hashes
    // stack: rlp_addr, chain_id_addr, retdest
    DUP1
    // stack: rlp_addr, after_blob_hashes_addr, chain_id_addr, retdest
    %decode_and_store_y_parity
    %decode_and_store_r
    %decode_and_store_s

    // stack: rlp_addr, after_blob_hashes_addr, chain_id_addr, retdest
    POP
    // stack: after_blob_hashes_addr, chain_id_addr, retdest

// From EIP-4844:
// The signature_y_parity, signature_r, signature_s elements of this transaction represent a secp256k1 signature over
// keccak256(0x03 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes]))
// We know that [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes] is already encoded
// at `chain_id_addr`; we just need to overwrite the existing RLP prefix. This is fine since we don't need the original encoding anymore.
type_3_compute_signed_data:
    // stack: after_blob_hashes_addr, chain_id_addr, retdest
    %prepend_rlp_list_prefix
    // stack: prefix_start_pos, rlp_len, retdest

    // Store a `3` in front of the RLP
    %decrement
    %stack (rlp_addr) -> (3, rlp_addr, rlp_addr)
    MSTORE_GENERAL
    // stack: rlp_addr, rlp_len, retdest

    // Hash the RLP + the leading `3`
    SWAP1 %increment SWAP1
    // stack: ADDR, len, retdest
    KECCAK_GENERAL
    // stack: hash, retdest

    %mload_txn_field(@TXN_FIELD_S)
    %mload_txn_field(@TXN_FIELD_R)
    %mload_txn_field(@TXN_FIELD_Y_PARITY) %add_const(27) // ecrecover interprets v as y_parity + 27

    PUSH store_origin
    // stack: store_origin, v, r, s, hash, retdest
    SWAP4
    // stack: hash, v, r, s, store_origin, retdest
    %jump(ecrecover)

store_origin:
    // stack: address, retdest
    // If ecrecover returned u256::MAX, that indicates failure.
    DUP1
    %eq_const(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    %jumpi(panic)

    // stack: address, retdest
    // EIP-4844: Deduct blob_gas_fee from the sender and burn it
    %compute_blob_gas_fee
    DUP2
    // stack: address, blob_gas_fee, address, retdest
    %deduct_eth
    // stack: deduct_eth_status, address, retdest
    %jumpi(panic)

    // stack: address, retdest
    %mstore_txn_field(@TXN_FIELD_ORIGIN)
    // stack: retdest
    %jump(process_normalized_txn)

%macro compute_blob_gas_fee
    PUSH @GAS_PER_BLOB
    %get_blob_versioned_hashes_list_length
    MUL
    PROVER_INPUT(blobbasefee)
    MUL
%endmacro

%macro get_blob_versioned_hashes_list_length
    // stack: (empty)
    PUSH 33 // encoded length of each blob versioned hash
    %mload_global_metadata(@GLOBAL_METADATA_BLOB_VERSIONED_HASHES_LEN)
    DIV
    // stack: len
%endmacro

%macro reset_blob_versioned_hashes
    // stack: (empty)
    // Reset the stored hashes
    %mload_global_metadata(@GLOBAL_METADATA_BLOB_VERSIONED_HASHES_LEN)
    PUSH @SEGMENT_TXN_BLOB_VERSIONED_HASHES // ctx 0
    %memset
    // Reset the global metadata
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_BLOB_VERSIONED_HASHES_LEN)
    // stack: (empty)
%endmacro