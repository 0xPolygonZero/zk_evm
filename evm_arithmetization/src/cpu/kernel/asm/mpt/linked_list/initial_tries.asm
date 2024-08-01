// Set the payload pointers of the leaves in the trie with root at `node_ptr` 
// to mem[payload_ptr_ptr] + step*i,
// for i =0..n_leaves. This is used to constraint the
// initial state and account tries payload pointers such that they are exactly
// those of the inital accounts and linked lists.
// Pre stack: node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
// Post stack: account_ptr_ptr, storage_ptr_ptr
global mpt_set_payload:
    // stack: node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    DUP1 %mload_trie_data
    // stack: node_type, node_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    // Increment node_ptr, so it points to the node payload instead of its type.
    SWAP1 %increment SWAP1
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest

    DUP1 %eq_const(@MPT_NODE_EMPTY)     %jumpi(skip)
    DUP1 %eq_const(@MPT_NODE_BRANCH)    %jumpi(set_payload_branch)
    DUP1 %eq_const(@MPT_NODE_EXTENSION) %jumpi(set_payload_extension)
    DUP1 %eq_const(@MPT_NODE_LEAF)      %jumpi(set_payload_leaf)

skip:
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    %stack (node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, account_ptr_ptr, storage_ptr_ptr)
    JUMP

%macro mpt_set_payload
    %stack(node_ptr, account_ptr_ptr, storage_ptr_ptr) -> (node_ptr, account_ptr_ptr, storage_ptr_ptr, %%after)
    %jump(mpt_set_payload)
%%after:
%endmacro

%macro set_initial_tries
    PUSH %%after
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %add_const(8) // The first node is the special node, of size 5, so the first value is at position 5 + 3.
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %add_const(6) // The first node is the special node, of size 4, so the first payload is at position 4 + 2.
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    %jump(mpt_set_payload)
%%after:
    // We store account_ptr_ptr - 2, i.e. a pointer to the first node not in the initial state.
    %sub_const(2)
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    // We store storage_ptr_ptr - 3, i.e. a pointer to the first node not in the initial state.
    %sub_const(3)
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN)
%endmacro

// Pre stack: node_ptr, account_ptr_ptr, retdest
// Post stack: storage_ptr_ptr
global mpt_set_storage_payload:
    // stack: node_ptr, storage_ptr_ptr, retdest
    DUP1 %mload_trie_data
    // stack: node_type, node_ptr, storage_ptr_ptr, retdest
    // Increment node_ptr, so it points to the node payload instead of its type.
    SWAP1 %increment SWAP1
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest

    DUP1 %eq_const(@MPT_NODE_EMPTY)     %jumpi(storage_skip)
    DUP1 %eq_const(@MPT_NODE_BRANCH)    %jumpi(set_payload_storage_branch)
    DUP1 %eq_const(@MPT_NODE_EXTENSION) %jumpi(set_payload_storage_extension)
    DUP1 %eq_const(@MPT_NODE_LEAF)      %jumpi(set_payload_storage_leaf)

storage_skip:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    %stack (node_type, after_node_type, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

%macro mpt_set_storage_payload
    %stack(node_ptr, storage_ptr_ptr) -> (node_ptr, storage_ptr_ptr, %%after)
    %jump(mpt_set_storage_payload)
%%after:
%endmacro

set_payload_branch:
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    POP

    // Call mpt_set_payload on each child
    %rep 16
        %stack
        (child_ptr_ptr, account_ptr_ptr, storage_ptr_ptr) -> 
        (child_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, child_ptr_ptr)
        // stack: child_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, child_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_ptr, account_ptr_ptr, storage_ptr_ptr, child_ptr_ptr, retdest
        %mpt_set_payload
        // stack: account_ptr_ptr', storage_ptr_ptr', child_ptr_ptr, retdest
        SWAP1
        SWAP2
        %increment
    %endrep
    // stack: child_ptr_ptr', account_ptr_ptr', storage_ptr_ptr', retdest
    %stack (child_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, account_ptr_ptr, storage_ptr_ptr)
    JUMP

set_payload_storage_branch:
    // stack: node_type, child_ptr_ptr, storage_ptr_ptr, retdest
    POP

    // Call mpt_set_storage_payload on each child
    %rep 16
        %stack
        (child_ptr_ptr, storage_ptr_ptr) -> 
        (child_ptr_ptr, storage_ptr_ptr, child_ptr_ptr)
        // stack: child_ptr_ptr, storage_ptr_ptr, child_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_ptr, storage_ptr_ptr, child_ptr_ptr, retdest
        %mpt_set_storage_payload
        // stack: storage_ptr_ptr', child_ptr_ptr, retdest
        SWAP1
        %increment
    %endrep
    // stack: child_ptr_ptr', storage_ptr_ptr', retdest
    %stack (child_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

set_payload_extension:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    POP
    // stack: after_node_type, storage_ptr_ptr, retdest
    %add_const(2) %mload_trie_data
    // stack: child_ptr, after_node_type, storage_ptr_ptr, retdest
    %jump(mpt_set_payload)
set_payload_storage_extension:
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    POP
    // stack: after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    %add_const(2) %mload_trie_data
    // stack: child_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %jump(mpt_set_storage_payload)

set_payload_leaf:
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    POP
    %add_const(2) // The payload pointer starts at index 3, after num_nibbles and packed_nibbles.
    DUP1 
    // stack payload_ptr_ptr, payload_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %mload_trie_data 
    // stack account_ptr, payload_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %add_const(2)
    %mload_trie_data // storage_root_ptr = account[2]

    DUP1 %mload_trie_data
    POP
    // stack storage_root_ptr, payload_ptr_ptr, account_ptr_ptr, storage_ptr_ptr, retdest
    %stack
        (storage_root_ptr, payload_ptr_ptr, account_ptr_ptr, storage_ptr_ptr) ->
        (storage_root_ptr, storage_ptr_ptr, after_set_storage_payload, storage_root_ptr, payload_ptr_ptr, account_ptr_ptr)
    %jump(mpt_set_storage_payload)
after_set_storage_payload:
    // stack: storage_ptr_ptr', storage_root_ptr, payload_ptr_ptr, account_ptr_ptr, retdest
    DUP4
    MLOAD_GENERAL // load the next payload pointer in the linked list
    DUP1 %add_const(2) // new_storage_root_ptr_ptr = payload_ptr[2]
    // stack: new_storage_root_ptr_ptr, new_payload_ptr, storage_root_ptr, storage_ptr_ptr', payload_ptr_ptr, account_ptr_ptr, retdest
    // Load also the old "dynamic" payload for storing the storage_root_ptr
    DUP6 %decrement
    MLOAD_GENERAL
    %add_const(2) // dyn_storage_root_ptr_ptr = dyn_paylod_ptr[2]
    %stack
        (dyn_storage_root_ptr_ptr, new_storage_root_ptr_ptr, new_payload_ptr, storage_ptr_ptr_p, storage_root_ptr, payload_ptr_ptr, account_ptr_ptr) ->
        (new_storage_root_ptr_ptr, storage_root_ptr, dyn_storage_root_ptr_ptr, storage_root_ptr, payload_ptr_ptr, new_payload_ptr, account_ptr_ptr, storage_ptr_ptr_p)
    %mstore_trie_data // The initial account pointer in the linked list has no storage root so we need to manually set it.
    %mstore_trie_data // The dynamic account pointer in the linked list has no storage root so we need to manually set it.
    %mstore_trie_data // Set the leaf payload pointing to next account in the linked list.
    // stack: account_ptr_ptr, storage_ptr_ptr', retdest
    %add_const(@STORAGE_NEXT_NODE_PTR) // The next pointer is at distance `STORAGE_NEXT_NODE_PTR`
    // stack: payload_ptr_ptr', storage_ptr_ptr', retdest
    SWAP1
    SWAP2
    JUMP

set_payload_storage_leaf:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    POP
    // stack: after_node_type, storage_ptr_ptr, retdest
    %add_const(2) // The value pointer starts at index 3, after num_nibbles and packed_nibbles.
    // stack: value_ptr_ptr, storage_ptr_ptr, retdest
    DUP2 MLOAD_GENERAL
    // stack: value, value_ptr_ptr, storage_ptr_ptr, retdest
    // If value == 0, then value_ptr = 0, and we don't need to append the value to the `TrieData` segment.
    DUP1 ISZERO %jumpi(set_payload_storage_leaf_end)
    %get_trie_data_size
    // stack: value_ptr, value, value_ptr_ptr, storage_ptr_ptr, retdest
    SWAP1
    %append_to_trie_data
set_payload_storage_leaf_end:
    // stack: value_ptr, value_ptr_ptr, storage_ptr_ptr, retdest
    SWAP1
    %mstore_trie_data
    // stack: storage_ptr_ptr, retdest
    %add_const(@STORAGE_LINKED_LISTS_NODE_SIZE) // The next pointer is at distance `STORAGE_LINKED_LISTS_NODE_SIZE`
    // stack: storage_ptr_ptr', retdest
    SWAP1
    JUMP
