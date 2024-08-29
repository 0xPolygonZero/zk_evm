// Hashing logic specific to a particular trie.

global mpt_hash_state_trie_new:
    // stack: cur_len, retdest
    %first_initial_slot
    SWAP1
    %first_initial_account
    SWAP1
    PUSH encode_account_new
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    // stack: node_ptr, encode_account_new, cur_len, next_addr_ptr, next_slot_ptr, retdest
    %jump(mpt_hash_new)

%macro mpt_hash_state_trie_new
    // stack: cur_len
    PUSH %%after
    SWAP1
    %jump(mpt_hash_state_trie_new)
%%after:
    %stack
        (hash, new_len, next_addr_ptr, next_slot_ptr) ->
        (next_addr_ptr, next_slot_ptr, hash, new_len)
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN)  
%endmacro

global mpt_hash_storage_trie_new:
    // stack: node_ptr, cur_len, next_slot_ptr, retdest
    %stack (node_ptr, cur_len) -> (node_ptr, encode_storage_value_new, cur_len)
    %jump(mpt_hash_storage)

%macro mpt_hash_storage_trie_new
    %stack (node_ptr, cur_len, next_slot_ptr) -> (node_ptr, cur_len, next_slot_ptr, %%after)
    %jump(mpt_hash_storage_trie_new)
%%after:
%endmacro

global encode_account_new:
    // stack: rlp_addr, value_ptr, cur_len, next_slot_ptr, retdest
    // First, we compute the length of the RLP data we're about to write.
    // We also update the length of the trie data segment.
    // The nonce and balance fields are variable-length, so we need to load them
    // to determine their contribution, while the other two fields are fixed
    // 32-bytes integers.

    // First, we add 4 to the trie data length, for the nonce,
    // the balance, the storage pointer and the code hash.
    SWAP2 %add_const(4) SWAP2

    // Now, we start the encoding.
    // stack: rlp_addr, value_ptr, cur_len, next_slot_ptr,  retdest
    DUP2 %mload_trie_data // nonce = value[0]
    %rlp_scalar_len
    // stack: nonce_rlp_len, rlp_addr, value_ptr, cur_len, next_slot_ptr, retdest
    DUP3 %increment %mload_trie_data // balance = value[1]
    %rlp_scalar_len
    // stack: balance_rlp_len, nonce_rlp_len, rlp_addr, value_ptr, cur_len, next_slot_ptr, retdest
    PUSH 66 // storage_root and code_hash fields each take 1 + 32 bytes
    ADD ADD
    // stack: payload_len, rlp_addr, value_ptr, cur_len, next_slot_ptr, retdest
    SWAP1
    // stack: rlp_addr, payload_len, value_ptr, cur_len, next_slot_ptr, retdest
    DUP2 %rlp_list_len
    // stack: list_len, rlp_addr, payload_len, value_ptr, cur_len, next_slot_ptr, retdest
    SWAP1
    // stack: rlp_addr, list_len, payload_len, value_ptr, cur_len, next_slot_ptr, retdest
    %encode_rlp_multi_byte_string_prefix
    // stack: rlp_pos_2, payload_len, value_ptr, cur_len, next_slot_ptr, retdest
    %encode_rlp_list_prefix
    // stack: rlp_pos_3, value_ptr, cur_len, next_slot_ptr, retdest
    DUP2 %mload_trie_data // nonce = value[0]
    // stack: nonce, rlp_pos_3, value_ptr, cur_len, next_slot_ptr, retdest
    SWAP1 %encode_rlp_scalar
    // stack: rlp_pos_4, value_ptr, cur_len, next_slot_ptr, retdest
    DUP2 %increment %mload_trie_data // balance = value[1]
    // stack: balance, rlp_pos_4, value_ptr, cur_len, next_slot_ptr, retdest
    SWAP1 %encode_rlp_scalar
    // stack: rlp_pos_5, value_ptr, cur_len, next_slot_ptr, retdest
    DUP3
    DUP3 %add_const(2) %mload_trie_data // storage_root_ptr = value[2]
    // stack: storage_root_ptr, cur_len, rlp_pos_5, value_ptr, cur_len, next_slot_ptr, retdest
    %stack
        (storage_root_ptr, cur_len, rlp_pos_5, value_ptr, cur_len, next_slot_ptr) ->
        (storage_root_ptr, cur_len, next_slot_ptr, rlp_pos_5, value_ptr, cur_len)

    // Hash storage trie.
    %mpt_hash_storage_trie_new

    // stack: storage_root_digest, new_len, next_slot_ptr, rlp_pos_5, value_ptr, cur_len, retdest
    %stack
        (storage_root_digest, new_len, next_slot_ptr, rlp_pos_five, value_ptr, cur_len) -> 
        (rlp_pos_five, storage_root_digest, value_ptr, new_len, next_slot_ptr)
    %encode_rlp_256
    // stack: rlp_pos_6, value_ptr, new_len, retdest
    SWAP1 %add_const(3) %mload_trie_data // code_hash = value[3]
    // stack: code_hash, rlp_pos_6, new_len, retdest
    SWAP1 %encode_rlp_256
    // stack: rlp_pos_7, new_len, retdest
    %stack(rlp_pos_7, new_len, next_slot_ptr, retdest) -> (retdest, rlp_pos_7, new_len, next_slot_ptr)
    JUMP

global encode_storage_value_new:
    // stack: rlp_addr, value, cur_len, retdest

    // A storage value is a scalar, so we only need to add 1 to the trie data length.
    SWAP2 %increment SWAP2

    // stack: rlp_addr, value, cur_len, retdest
    // The YP says storage trie is a map "... to the RLP-encoded 256-bit integer values"
    // which seems to imply that this should be %encode_rlp_256. But %encode_rlp_scalar
    // causes the tests to pass, so it seems storage values should be treated as variable-
    // length after all.
    %doubly_encode_rlp_scalar
    // stack: rlp_addr', cur_len, retdest
    %stack (rlp_addr, cur_len, retdest) -> (retdest, rlp_addr, cur_len)
    JUMP

