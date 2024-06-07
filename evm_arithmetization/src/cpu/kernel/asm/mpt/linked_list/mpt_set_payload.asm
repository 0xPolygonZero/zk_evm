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

%macro mpt_set_payload_no_return
    PUSH %%after
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %add_const(7) // The first node is the special node, of size 5, so the first payload is at position 5 + 2.
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %add_const(5) // The first node is the special node, of size 4, so the first payload is at position 4 + 1.
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    %jump(mpt_set_payload)
%%after:
    %pop2
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
    DUP1 %eq_const(@MPT_NODE_EXTENSION) %jumpi(set_payload_extension)
    DUP1 %eq_const(@MPT_NODE_LEAF)      %jumpi(set_payload_storage_leaf)

storage_skip:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    %stack (node_type, after_node_type, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

%macro mpt_set_storage_payload
    %stack(node_ptr, storage_ptr_ptr) -> (node_ptr, storage_ptr_ptr, %%after)
    %jump(mpt_set_payload)
%%after:
%endmacro

global set_payload_branch:
    // stack: node_type, after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    POP

    // Call encode_or_hash_node on each child
    %rep 16
        %stack
        (after_node_type, account_ptr_ptr, storage_ptr_ptr) -> 
        (after_node_type, account_ptr_ptr, storage_ptr_ptr, after_node_type)
        // stack: after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_i_ptr, account_ptr_ptr, storage_ptr_ptr, %%after_encode, after_node_type, retdest
        %mpt_set_payload
        // stack: account_ptr_ptr', storage_ptr_ptr', after_node_type, retdest
        SWAP1
        SWAP2
        %increment
    %endrep
    // stack: after_node_type', account_ptr_ptr', storage_ptr_ptr', retdest
    %stack (after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest) -> (retdest, account_ptr_ptr, storage_ptr_ptr)
    JUMP

set_payload_storage_branch:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    POP

    // Call encode_or_hash_node on each child
    %rep 16
        %stack
        (after_node_type, storage_ptr_ptr) -> 
        (after_node_type, storage_ptr_ptr, after_node_type)
        // stack: after_node_type, storage_ptr_ptr, retdest
        %mload_trie_data
        // stack: child_i_ptr, storage_ptr_ptr, %%after_encode, after_node_type, retdest
        %mpt_set_storage_payload
        // stack: storage_ptr_ptr', after_node_type, retdest
        SWAP1
        %increment
    %endrep
    // stack: after_node_type', storage_ptr_ptr', retdest
    %stack (after_node_type, storage_ptr_ptr, retdest) -> (retdest, storage_ptr_ptr)
    JUMP

set_payload_extension:
    // stack: node_type, after_node_type, (account_ptr_ptr,) storage_ptr_ptr, retdest
    POP
    // stack: after_node_type, account_ptr_ptr, storage_ptr_ptr, retdest
    %add_const(2) %mload_trie_data
    // stack: child_ptr, (account_ptr_ptr,) storage_ptr_ptr, retdest
    %jump(mpt_set_payload)

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
    %stack
        (new_storage_root_ptr_ptr, new_payload_ptr, storage_ptr_ptr_p, storage_root_ptr, payload_ptr_ptr, account_ptr_ptr) ->
        (new_storage_root_ptr_ptr, storage_root_ptr, payload_ptr_ptr, new_payload_ptr, account_ptr_ptr, storage_ptr_ptr_p)
    %mstore_trie_data // The account in the linked list has no storage root so we need to manually set it.
    %mstore_trie_data // Set the leaf payload pointing to next account in the linked list.
    // stack: account_ptr_ptr, storage_ptr_ptr', retdest
    %add_const(4) // The next pointer is at distance 4
    // stack: payload_ptr_ptr', storage_ptr_ptr', retdest
    SWAP1
    SWAP2
    JUMP

set_payload_storage_leaf:
    // stack: node_type, after_node_type, storage_ptr_ptr, retdest
    POP
    // stack:  after_node_type, storage_ptr_ptr, retdest
    %add_const(2) // The value pointer starts at index 3, after num_nibbles and packed_nibbles.
    DUP2
    MLOAD_GENERAL
    SWAP1
    %mstore_trie_data
    // stack: storage_ptr_ptr, retdest
    %add_const(5) // The next pointer is at distance 5
    // stack: storage_ptr_ptr', retdest
    SWAP1
    JUMP