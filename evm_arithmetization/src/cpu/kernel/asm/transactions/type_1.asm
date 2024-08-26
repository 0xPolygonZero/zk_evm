// Type 1 transactions, introduced by EIP 2930, have the format
//     0x01 || rlp([chain_id, nonce, gas_price, gas_limit, to, value, data,
//                  access_list, y_parity, r, s])
//
// The signed data is
//     keccak256(0x01 || rlp([chain_id, nonce, gas_price, gas_limit, to, value,
//                            data, access_list]))

global process_type_1_txn:
    // stack: rlp_addr, retdest
    // Initial rlp address offset of 1 (skipping over the 0x01 byte)
    %add_const(1)
    // stack: rlp_addr, retdest
    %decode_rlp_list_len
    // We don't actually need the length.
    %stack (rlp_addr, len) -> (rlp_addr)

    %store_chain_id_present_true
    // stack: rlp_addr, retdest
    DUP1
    // stack: rlp_addr, chain_id_addr, retdest
    %decode_and_store_chain_id
    %decode_and_store_nonce
    %decode_and_store_gas_price_legacy
    %decode_and_store_gas_limit
    %decode_and_store_to
    %decode_and_store_value
    %decode_and_store_data
    %decode_and_store_access_list
    // stack: rlp_addr, chain_id_addr, retdest
    DUP1
    // stack: rlp_addr, after_access_list_addr, chain_id_addr, retdest
    %decode_and_store_y_parity
    %decode_and_store_r
    %decode_and_store_s

    // stack: rlp_addr, after_access_list_addr, chain_id_addr, retdest
    POP
    // stack: after_access_list_addr, chain_id_addr, retdest

// From EIP-2930:
// The signatureYParity, signatureR, signatureS elements of this transaction represent a secp256k1 signature
// over keccak256(0x01 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList])).
// We know that [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList] is already encoded
// at `chain_id_addr`; we just need to overwrite the existing RLP prefix. This is fine since we don't
// need the original encoding anymore.
type_1_compute_signed_data:
    // stack: after_access_list_addr, chain_id_addr, retdest
    %prepend_rlp_list_prefix
    // stack: prefix_start_rlp_addr, rlp_len, retdest

    // Store a `1` in front of the RLP
    %decrement
    %stack (rlp_addr) -> (1, rlp_addr, rlp_addr)
    MSTORE_GENERAL
    // stack: rlp_addr, rlp_len, retdest

    // Hash the RLP + the leading `1`
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
    %mstore_txn_field(@TXN_FIELD_ORIGIN)
    // stack: retdest
    %jump(process_normalized_txn)
