
global set_initial_state_trie:
    // stack: retdest
    PUSH set_initial_state_trie_after
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    %first_initial_node // Skip the first node.
    %jump(insert_all_initial_nodes)
set_initial_state_trie_after:
    //stack: new_state_root
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    JUMP

%macro set_initial_state_trie
    // stack: (empty)
    PUSH %%after
    %jump(set_initial_state_trie)
%%after:
%endmacro

// Given a pointer `root_ptr` to the root of a trie, insert all the initial nodes in
// the state_linked_list starting at `node_ptr_ptr`.
// Pre stack: node_ptr_ptr, root_ptr, retdest
// Post stack: new_root_ptr. // The value of new_root_ptr shouldn't change
global insert_all_initial_nodes:
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
    %split_key
    // stack: k0, k1, k2, k3, after_smt_read, key, root_ptr, node_ptr_ptr, retdest
    PUSH 0
    DUP8
    // stack: root_ptr, level, k0, k1, k2, k3, after_smt_read, key, root_ptr, node_ptr_ptr, retdest
    %jump(smt_read)
after_smt_read:
    //stack: trie_value_ptr_ptr, key, root_ptr, node_ptr_ptr, retdest
    DUP4
    %add_const(2) // Get the initial value
    MLOAD_GENERAL
    SWAP1
    %mstore_trie_data
    // stack: key, root_ptr, node_ptr_ptr, retdest
    POP
    SWAP1
    %next_initial_node
    // stack: node_ptr_ptr', root_ptr, retdest
    %jump(insert_all_initial_nodes)

no_more_nodes:
    // stack: key, root_ptr, node_ptr_ptr, retdest
    %stack (key, root_ptr, node_ptr_ptr, retdest) ->(retdest, root_ptr)
    JUMP