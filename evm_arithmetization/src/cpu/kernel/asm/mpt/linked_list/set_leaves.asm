// Set the trie with root at `node_ptr` leaves 
// payloads pointers to mem[payload_ptr_ptr] + step*i, for
// for i =0..n_leaves. This is used to constraint that the
// initial state and account tries payload pointers are exactly
// those of the inital accounts and linked lists
// Pre stack: node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
// Post stack: account_ptr_ptr, storage_ptr_ptr
global mpt_set_payload:
    // stack: node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    DUP1 %mload_trie_data
    // stack: node_type, node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    // Increment node_ptr, so it points to the node payload instead of its type.
    SWAP1 %increment SWAP1
    // stack: node_type, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest

    DUP1 %eq_const(@MPT_NODE_EMPTY)     %jumpi(skip)
    DUP1 %eq_const(@MPT_NODE_BRANCH)    %jumpi(set_payload_branch)
    DUP1 %eq_const(@MPT_NODE_EXTENSION) %jumpi(set_payload_extension)
    DUP1 %eq_const(@MPT_NODE_LEAF)      %jumpi(set_payload_leaf)

skip:
    // stack: node_type, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %stack (node_type, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, account_ptr_ptr, storage_ptr_ptr)
    JUMP

// Pre stack: node_ptr, account_ptr_ptr, retdest
// Post stack: storage_ptr_ptr
global mpt_set_storage_payload:
    // stack: node_ptr, storage_ptr_ptr, retdest
    DUP1 %mload_trie_data
    // stack: node_type, node_ptr, storage_ptr_ptr, retdest
    // Increment node_ptr, so it points to the node payload instead of its type.
    SWAP1 %increment SWAP1
    // stack: node_type, node_payload_ptr, storage_ptr_ptr, retdest

    DUP1 %eq_const(@MPT_NODE_EMPTY)     %jumpi(storage_skip)
    DUP1 %eq_const(@MPT_NODE_BRANCH)    %jumpi(set_payload_storage_branch)
    DUP1 %eq_const(@MPT_NODE_EXTENSION) %jumpi(set_payload_extension)
    DUP1 %eq_const(@MPT_NODE_LEAF)      %jumpi(set_payload_storage_leaf)

storage_skip:
    // stack: node_type, node_payload_ptr, storage_ptr_ptr, retdest
    %stack (node_type, node_payload_ptr, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

global set_payload_branch:
    // stack: node_type, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    POP

    // Call encode_or_hash_node on each child
    %rep 16
        %stack
        (node_payload_ptr, account_ptr_ptr, storage_ptr_ptr) -> 
        (node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, %%after_mpt_set_payload, node_payload_ptr)
        // stack: node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_i_ptr, account_ptr_ptr, storage_ptr_ptr, %%after_encode, node_payload_ptr, retdest
        %jump(mpt_set_payload)
    %%after_mpt_set_payload:
        // stack: account_ptr_ptr', storage_ptr_ptr', node_payload_ptr, retdest
        SWAP1
        SWAP2
        %increment
    %endrep
    // stack: node_payload_ptr', account_ptr_ptr', storage_ptr_ptr', retdest
    %stack (node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, account_ptr_ptr, storage_ptr_ptr)
    JUMP

global set_payload_storage_branch:
    // stack: node_type, node_payload_ptr, storage_ptr_ptr, retdest
    POP

    // Call encode_or_hash_node on each child
    %rep 16
        %stack
        (node_payload_ptr, storage_ptr_ptr) -> 
        (node_payload_ptr, storage_ptr_ptr, %%after_mpt_set_payload, node_payload_ptr)
        // stack: node_payload_ptr, storage_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_i_ptr, storage_ptr_ptr, %%after_encode, node_payload_ptr, retdest
        %jump(mpt_set_payload)
    %%after_mpt_set_payload:
        // stack: storage_ptr_ptr', node_payload_ptr, retdest
        SWAP1
        %increment
    %endrep
    // stack: node_payload_ptr', storage_ptr_ptr', retdest
    %stack (node_payload_ptr, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

set_payload_extension:
    // stack: node_type, node_payload_ptr, (account_ptr_ptr,) storage_ptr_ptr, retdest
    POP
    // stack: node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %add_const(2) %mload_trie_data
    // stack: child_ptr, (account_ptr_ptr,) storage_ptr_ptr, retdest
    %jump(mpt_set_payload)

set_payload_leaf:
    // stack: node_type, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    POP
    // stack:  node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    DUP1 %add_const(2) // The value pointer starts at index 3, after num_nibbles and packed_nibbles.
    MLOAD_GENERAL
    // stack value_ptr, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %add_const(2) %mload_trie_data // storage_root_ptr = value[2]
    // stack storage_root_ptr, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %stack
        (storage_root_ptr, node_payload_ptr, account_ptr_ptr, storage_ptr_ptr) ->
        (storage_root_ptr, storage_ptr_ptr, after_set_storage_payload, node_payload_ptr, account_ptr_ptr)
    %jump(mpt_set_storage_payload)
after_set_storage_payload:
    // stack: storage_ptr_ptr', node_payload_ptr, account_ptr_ptr, retdest
    SWAP2 SWAP1

    %add_const(2)
    DUP2
    MSTORE_GENERAL
    // stack: account_ptr_ptr, storage_ptr_ptr', retdest
    %add_const(5) // The next pointer is at distance 4
    // stack: payload_ptr_ptr', storage_ptr_ptr', retdest
    SWAP1
    SWAP2
    JUMP

set_payload_storage_leaf:
    // stack: node_type, node_payload_ptr, storage_ptr_ptr, retdest
    POP
    // stack:  node_payload_ptr, storage_ptr_ptr, retdest
    %add_const(2) // The value pointer starts at index 3, after num_nibbles and packed_nibbles.
    DUP2
    MSTORE_GENERAL
    // stack: storage_ptr_ptr, retdest
    %add_const(5) // The next pointer is at distance 5
    // stack: storage_ptr_ptr', retdest
    SWAP1
    JUMP