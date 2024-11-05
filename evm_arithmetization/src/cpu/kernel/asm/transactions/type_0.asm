// Type 0 transactions, aka legacy transaction, have the format
//     rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s])
//
// The field v was originally encoded as
//     27 + y_parity
// but as of EIP 155 it can also be encoded as
//     35 + 2 * chain_id + y_parity
//
// If a chain_id is present in v, the signed data is
//     keccak256(rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]))
// otherwise, it is
//     keccak256(rlp([nonce, gas_price, gas_limit, to, value, data]))

global process_type_0_txn:
    // stack: rlp_addr, retdest
    // Store txn type.
    PUSH 0
    %mstore_txn_field(@TXN_FIELD_TYPE)

    // stack: rlp_addr, retdest
    %decode_rlp_list_len
    // We don't actually need the length.
    %stack (rlp_addr, len) -> (rlp_addr)

    // stack: rlp_addr, retdest
    // Keep track of the nonce position.
    DUP1
    // stack: rlp_addr, nonce_addr, retdest
    %decode_and_store_nonce
    %decode_and_store_gas_price_legacy
    %decode_and_store_gas_limit
    %decode_and_store_to
    %decode_and_store_value
    %decode_and_store_data
    // stack: rlp_addr, nonce_addr, retdest
    DUP1

    // Parse the "v" field.
    // stack: rlp_addr, after_data_addr, nonce_addr, retdest
    %decode_rlp_scalar
    // stack: rlp_addr, v, after_data_addr, nonce_addr, retdest
    SWAP1
    // stack: v, rlp_addr, after_data_addr, nonce_addr, retdest
    DUP1
    %gt_const(28)
    // stack: v > 28, v, rlp_addr, after_data_addr, nonce_addr, retdest
    %jumpi(process_v_new_style)

    // We have an old style v, so y_parity = v - 27.
    // No chain ID is present, so we can leave TXN_FIELD_CHAIN_ID_PRESENT and
    // TXN_FIELD_CHAIN_ID with their default values of zero.
    // stack: v, rlp_addr, after_data_addr, nonce_addr, retdest
    %sub_const(27)
    %mstore_txn_field(@TXN_FIELD_Y_PARITY)

    // stack: rlp_addr, after_data_addr, nonce_addr, retdest
    %jump(decode_r_and_s)

process_v_new_style:
    // stack: v, rlp_addr, after_data_addr, nonce_addr, retdest
    // We have a new style v, so chain_id_present = 1,
    // chain_id = (v - 35) / 2, and y_parity = (v - 35) % 2.
    %stack (v, rlp_addr) -> (1, v, rlp_addr)
    %mstore_txn_field(@TXN_FIELD_CHAIN_ID_PRESENT)

    // stack: v, rlp_addr, after_data_addr, nonce_addr, retdest
    %sub_const(35)
    DUP1
    // stack: v - 35, v - 35, rlp_addr, after_data_addr, nonce_addr, retdest
    %div2
    // stack: chain_id, v - 35, rlp_addr, after_data_addr, nonce_addr, retdest
    %mstore_txn_field(@TXN_FIELD_CHAIN_ID)

    // stack: v - 35, rlp_addr, after_data_addr, nonce_addr, retdest
    %mod_const(2)
    // stack: y_parity, rlp_addr, after_data_addr, nonce_addr, retdest
    %mstore_txn_field(@TXN_FIELD_Y_PARITY)

decode_r_and_s:
    // stack: rlp_addr, after_data_addr, nonce_addr, retdest
    %decode_and_store_r
    %decode_and_store_s
    // stack: rlp_addr, after_data_addr, nonce_addr, retdest
    POP
    // stack: after_data_addr, nonce_addr, retdest

type_0_compute_signed_data:
    // If a chain_id is present in v, the signed data is
    //     keccak256(rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]))
    // otherwise, it is
    //     keccak256(rlp([nonce, gas_price, gas_limit, to, value, data]))
    // We know that [nonce, gas_price, gas_limit, to, value, data] is already encoded
    // at `nonce_addr`.

    // If there is a `chain_id`, we append it at the end. This will overwrite `v`, `r` and `s`
    // but the transaction has already been inserted in the MPT so it's not an issue.
    // stack: after_data_addr, nonce_addr, retdest
    %mload_txn_field(@TXN_FIELD_CHAIN_ID_PRESENT)
    ISZERO %jumpi(finish_rlp_list)
    // stack: after_data_addr, nonce_addr, retdest
    %mload_txn_field(@TXN_FIELD_CHAIN_ID)
    %encode_rlp_scalar_swapped_inputs
    // stack: rlp_signed_end_addr, nonce_addr, retdest

    PUSH 0
    %encode_rlp_scalar_swapped_inputs
    // stack: rlp_signed_end_addr, rlp_addr_start, retdest

    PUSH 0
    %encode_rlp_scalar_swapped_inputs
    // stack: rlp_signed_end_addr, rlp_addr_start, retdest

finish_rlp_list:
    // stack: rlp_signed_end_addr, rlp_addr_start, retdest
    // We will overwrite the original transaction RLP prefix. This is fine since we don't need the
    // original encoding anymore.
    %prepend_rlp_list_prefix
    // stack: ADDR, rlp_len, retdest
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
