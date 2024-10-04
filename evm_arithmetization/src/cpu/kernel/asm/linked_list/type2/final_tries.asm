// Given a pointer `root_ptr` to the root of a trie, insert all the final nodes in
// the state_linked_list starting at `node_ptr_ptr`.
// Pre stack: node_ptr_ptr, root_ptr, retdest
// Post stack: new_root_ptr. // The value of new_root_ptr shouldn't change
global insert_all_final_nodes:
    // stack: node_ptr_ptr, root_ptr, retdest
    SWAP1 DUP2
    MLOAD_GENERAL
    // stack: key, root_ptr, node_ptr_ptr, retdest
    DUP3
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    EQ
    %jumpi(no_more_nodes)
    // stack: key, root_ptr, node_ptr_ptr, retdest
    PUSH after_smt_read
    DUP2
    PUSH 64
    DUP5
    // stack: root_ptr, nibbles, key, after_smt_read, key, root_ptr, node_ptr_ptr, retdest
    %jump(smt_read)
after_smt_read:
    //stack: trie_value_ptr_ptr, key, root_ptr, node_ptr_ptr, retdest
    DUP4
    %increment // Get the final value
    SWAP1
    %mstore_trie_data
    // stack: key, root_ptr, node_ptr_ptr, retdest
    POP
    SWAP1
    %next_node
    // stack: node_ptr_ptr', root_ptr, retdest
    %jump(insert_all_initial_nodes)

no_more_nodes:
    // stack: key, root_ptr, node_ptr_ptr, retdest
    %stack (key, root_ptr, node_ptr_ptr, retdest) ->(retdest, root_ptr)
    JUMP

// Delete all the values in the final state linked list which where deleted from the initial state.
// Pre stack: node_ptr_ptr, root_ptr, retdest
// Post stack: new_root_ptr.
global delete_removed_nodes:
    // stack: node_ptr_ptr, root_ptr, retdest
    DUP1
    // We assume that the size of the initial state linked list, containing the nodes
    // of the initial state, was stored at `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`.
    %mload_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    // The initial state linked list was stored at and addresses smaller than `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`.
    // If we also know that `@SEGMENT_ACCOUNT_LINKED_LIST <= node_ptr_ptr`, for deleting node at `node_ptr_ptr` it
    // suffices to check that `node_ptr_ptr` != `@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN`
    EQ
    %jumpi(delete_removed_nodes_end)
    // stack: node_ptr_ptr, root_ptr, retdest
    DUP1
    %next_node
    %eq_const(@U256_MAX) // If the next node pointer is @U256_MAX, the node was deleted
    %jumpi(delete_node)
    // stack: node_ptr_ptr, root_ptr, retdest
    %next_initial_node
    %jump(delete_removed_nodes)

delete_removed_nodes_end:
    // stack: account_ptr_ptr, root_ptr, retdest
    %stack (node_ptr_ptr, root_ptr, retdest) -> (retdest, root_ptr)
    JUMP

delete_node:
    // stack: node_ptr_ptr, root_ptr, retdest
    DUP1
    MLOAD_GENERAL
    %stack (key, node_ptr_ptr, root_ptr) -> (root_ptr, 64, key, after_mpt_delete, node_ptr_ptr)
    %jump(mpt_delete)
after_mpt_delete:
    // stack: root_ptr', node_ptr_ptr, retdest
    SWAP1
    %next_initial_node
    %jump(delete_removed_nodes)


global set_final_tries:
    PUSH set_final_tries_after
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    %first_initial_node // Skip the first node.
    %jump(delete_removed_nodes)
set_final_tries_after:
    // stack: new_state_root
    PUSH set_final_tries_after_after SWAP1
    // stack: new_state_root, set_final_tries_after_after
    %first_node
    %jump(insert_all_final_nodes)
set_final_tries_after_after:
    //stack: new_state_root
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    JUMP

%macro set_final_tries
    // stack: (empty)
    PUSH %%after
    %jump(set_final_tries)
%%after:
%endmacro
