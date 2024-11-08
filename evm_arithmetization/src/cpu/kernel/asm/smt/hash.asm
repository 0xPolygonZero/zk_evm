%macro hash_state_trie
    %stack (cur_len) -> (cur_len, %%after)
    %jump(hash_state_trie)
%%after:
%endmacro

// Root hash of the state SMT.
global hash_state_trie:
    // stack: cur_len, retdest
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)

// Root hash of SMT stored at `trie_data[ptr]`.
// Pseudocode:
// ```
// hash( HashNode { h } ) = h
// hash( InternalNode { left, right } ) = Poseidon(hash(left) || hash(right) || [0,0,0,0])
// hash( Leaf { rem_key, val_hash } ) = Poseidon(rem_key || val_hash || [1,0,0,0])
// ```
global smt_hash:
    // stack: ptr, cur_len, retdest
    DUP1
    %mload_trie_data
    // stack: node, node_ptr, cur_len, retdest
    DUP1 %eq_const(@SMT_NODE_HASH)     %jumpi(smt_hash_hash)
    DUP1 %eq_const(@SMT_NODE_INTERNAL) %jumpi(smt_hash_internal)
         %eq_const(@SMT_NODE_LEAF)     %jumpi(smt_hash_leaf)
smt_hash_unknown_node_type:
    PANIC

smt_hash_hash:
global debug_hash_hash:
    // stack: node, node_ptr, cur_len, retdest
    POP
    // stack: node_ptr, cur_len, retdest
    DUP1 ISZERO %jumpi(empty_hash_node) // We don't count empty hash nodes
    SWAP1 %add_const(2) SWAP1
empty_hash_node:
    // stack: node_ptr, cur_len, retdest
    %increment
    // stack: node_ptr+1, cur_len, retdest
    %mload_trie_data
    %stack (hash, cur_len, retdest) -> (retdest, hash, cur_len)
    JUMP

smt_hash_internal:
global debug_hash_internal:
    // stack: node, node_ptr, cur_len, retdest
    POP
    // stack: node_ptr, cur_len, retdest
    SWAP1 %add_const(3) SWAP1
    %increment
    // stack: node_ptr+1, cur_len, retdest
    DUP1
    %mload_trie_data
    %stack (left_child_ptr, node_ptr_plus_1, cur_len, retdest) -> (left_child_ptr, cur_len, smt_hash_internal_after_left, node_ptr_plus_1, retdest)
    %jump(smt_hash)
smt_hash_internal_after_left:
global debug_hash_internal_after_left:
    %stack (left_hash, cur_len, node_ptr_plus_1, retdest) -> (node_ptr_plus_1, left_hash, cur_len, retdest)
    %increment
    // stack: node_ptr+2, left_hash, cur_len, retdest
    %mload_trie_data
    %stack (right_child_ptr, left_hash, cur_len, retdest) -> (right_child_ptr, cur_len, smt_hash_internal_after_right, left_hash, retdest)
    %jump(smt_hash)
smt_hash_internal_after_right:
global debug_hash_internal_after_right:
    %stack (right_hash, cur_len, left_hash) -> (left_hash, right_hash, 0, cur_len)
    POSEIDON
    %stack (hash, cur_len, retdest) -> (retdest, hash, cur_len)
    JUMP

smt_hash_leaf:
global debug_hash_leaf:
    // stack: node_ptr, cur_len, retdest
    SWAP1 %add_const(3) SWAP1
    // stack: node_ptr, cur_len, retdest
    %increment
    // stack: node_ptr+1, cur_len, retdest
    DUP1 %increment
    // stack: node_ptr+2, node_ptr+1, cur_len, retdest
    %mload_trie_data
    // stack: value, node_ptr+1, cur_len, retdest
    SWAP1
    // stack: node_ptr+1, value, cur_len, retdest
    %mload_trie_data
    %stack (rem_key, value) -> (value, smt_hash_leaf_contd, rem_key)
    %jump(hash_limbs)
smt_hash_leaf_contd:
    %stack (value_hash, rem_key) -> (rem_key, value_hash, 1)
    POSEIDON
    %stack (hash, cur_len, retdest) -> (retdest, hash, cur_len)
    JUMP
