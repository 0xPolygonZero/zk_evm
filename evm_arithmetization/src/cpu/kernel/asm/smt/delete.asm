%macro smt_delete_state
    %stack (key) -> (key, %%after)
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT) // node_ptr
    // stack: node_ptr, key, retdest
    %jump(smt_delete)
%%after:
    // stack: new_node_ptr
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    // stack: (emtpy)
%endmacro

// Return a copy of the given node with the given key deleted.
// Assumes that the key is in the SMT.
//
// Pre stack: node_ptr, key, retdest
// Post stack: updated_node_ptr
global smt_delete:
    // stack: node_ptr, key, retdest
    SWAP1 %split_key
    %stack (k0, k1, k2, k3, node_ptr) -> (node_ptr, 0, k0, k1, k2, k3)
smt_delete_with_keys:
    // stack: node_ptr, level, ks, retdest
    DUP1 %mload_trie_data
    // stack: node_type, node_ptr, level, ks, retdest
    // Increment node_ptr, so it points to the node payload instead of its type.
    SWAP1 %increment SWAP1
    // stack: node_type, node_payload_ptr, level, ks, retdest

    DUP1 %eq_const(@SMT_NODE_INTERNAL)  %jumpi(smt_delete_internal)
         %eq_const(@SMT_NODE_LEAF)      %jumpi(smt_delete_leaf)
    PANIC // Should never happen.

smt_delete_leaf:
    // stack: node_payload_ptr, level, ks, retdest
    %pop6
    PUSH 0 // empty node ptr
    SWAP1 JUMP

smt_delete_internal:
    // stack: node_type, node_payload_ptr, level, ks, retdest
    POP
    // stack: node_payload_ptr, level, ks, retdest
    DUP2 %and_const(3) // level mod 4
    // stack: level%4, node_payload_ptr, level, ks, retdest
    DUP1 %eq_const(0) %jumpi(smt_delete_internal_0)
    DUP1 %eq_const(1) %jumpi(smt_delete_internal_1)
    DUP1 %eq_const(2) %jumpi(smt_delete_internal_2)
         %eq_const(3) %jumpi(smt_delete_internal_3)
    PANIC
smt_delete_internal_0:
    // stack: level%4, node_payload_ptr, level, ks, retdest
    %stack (level_mod_4, node_payload_ptr, level, k0, k1, k2, k3 ) -> (k0, node_payload_ptr, level, k0, k1, k2, k3 )
    %pop_bit
    %stack (bit, newk0, node_payload_ptr, level, k0, k1, k2, k3 ) -> (bit, node_payload_ptr, level, newk0, k1, k2, k3 )
    %jump(smt_delete_internal_contd)
smt_delete_internal_1:
    %stack (level_mod_4, node_payload_ptr, level, k0, k1, k2, k3 ) -> (k1, node_payload_ptr, level, k0, k1, k2, k3 )
    %pop_bit
    %stack (bit, newk1, node_payload_ptr, level, k0, k1, k2, k3 ) -> (bit, node_payload_ptr, level, k0, newk1, k2, k3 )
    %jump(smt_delete_internal_contd)
smt_delete_internal_2:
    %stack (level_mod_4, node_payload_ptr, level, k0, k1, k2, k3 ) -> (k2, node_payload_ptr, level, k0, k1, k2, k3 )
    %pop_bit
    %stack (bit, newk2, node_payload_ptr, level, k0, k1, k2, k3 ) -> (bit, node_payload_ptr, level, k0, k1, newk2, k3 )
    %jump(smt_delete_internal_contd)
smt_delete_internal_3:
    %stack (node_payload_ptr, level, k0, k1, k2, k3 ) -> (k3, node_payload_ptr, level, k0, k1, k2, k3 )
    %pop_bit
    %stack (bit, newk3, node_payload_ptr, level, k0, k1, k2, k3 ) -> (bit, node_payload_ptr, level, k0, k1, k2, newk3 )
smt_delete_internal_contd:
    //stack: bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    PUSH internal_update
    //stack: internal_update, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %rep 7
        DUP8
    %endrep
    //stack: bit, node_payload_ptr, level, k0, k1, k2, k3, internal_update, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    ADD
    //stack: child_ptr_ptr, level, k0, k1, k2, k3, internal_update, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %mload_trie_data
    //stack: child_ptr, level, k0, k1, k2, k3, internal_update, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    SWAP1 %increment SWAP1
    //stack: child_ptr, level+1, k0, k1, k2, k3, internal_update, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %jump(smt_delete_with_keys)

// Update the internal node, possibly deleting it, or returning a leaf node.
internal_update:
    // Update the child first.
    //stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP2 PUSH 1 SUB
    //stack: 1-bit, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP4 ADD
    //stack: sibling_ptr_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %mload_trie_data DUP1 %mload_trie_data
    //stack: sibling_node_type, sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP1 %eq_const(@SMT_NODE_HASH)     %jumpi(sibling_is_hash)
    DUP1 %eq_const(@SMT_NODE_LEAF)     %jumpi(sibling_is_leaf)
         %eq_const(@SMT_NODE_INTERNAL) %jumpi(sibling_is_internal)
    PANIC // Should never happen.
sibling_is_internal:
    //stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
insert_child:
    //stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %stack (deleted_child_ptr, bit, node_payload_ptr) -> (node_payload_ptr, bit, deleted_child_ptr, node_payload_ptr)
    ADD %mstore_trie_data
    // stack: node_payload_ptr, level, ks, retdest
    %decrement
    %stack (node_ptr, level, k0, k1, k2, k3, retdest) -> (retdest, node_ptr)
    JUMP

sibling_is_hash:
    // stack: sibling_node_type, sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    //stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %increment %mload_trie_data
    // stack: hash, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %jumpi(insert_child) // Sibling is non-empty hash node.
sibling_is_empty:
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP1 %mload_trie_data
    // stack: deleted_child_node_type, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP1 %eq_const(@SMT_NODE_HASH) %jumpi(sibling_is_empty_child_is_hash)
    DUP1 %eq_const(@SMT_NODE_LEAF) %jumpi(sibling_is_empty_child_is_leaf)
sibling_is_empty_child_is_internal:
    // stack: deleted_child_node_type, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %jump(insert_child)

sibling_is_empty_child_is_hash:
    // stack: deleted_child_node_type, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP1 %increment %mload_trie_data
    // stack: hash, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %jumpi(insert_child)
sibling_is_empty_child_is_empty:
    // We can just delete this node.
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %pop8
    SWAP1 PUSH 0
    // stack: retdest, 0
    JUMP

sibling_is_empty_child_is_leaf:
    // stack: deleted_child_node_type, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %increment
    // stack: deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP4
    // stack: level, deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP3
    // stack: bit, level, deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP3 %mload_trie_data
    // stack: child_key, bit, level, deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %recombine_key
    // stack: new_child_key, deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP2 %mstore_trie_data
    // stack: deleted_child_key_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %decrement
    // stack: deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    SWAP7
    // stack: k3, bit, node_payload_ptr, level, k0, k1, k2, deleted_child_ptr, retdest
    %pop7
    // stack: deleted_child_ptr, retdest
    SWAP1 JUMP

sibling_is_leaf:
    // stack: sibling_node_type, sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    // stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    DUP2 %is_non_empty_node
    // stack: child_is_non_empty, sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %jumpi(sibling_is_leaf_child_is_non_empty)
sibling_is_leaf_child_is_empty:
    // stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    %increment
    // stack: sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP5
    // stack: level, sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP4
    // stack: bit, level, sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    PUSH 1 SUB
    // stack: obit, level, sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP3 %mload_trie_data
    // stack: sibling_key, obit, level, sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %recombine_key
    // stack: new_key, sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    DUP2 %mstore_trie_data
    // stack: sibling_key_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    %decrement
    // stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, k3, retdest
    SWAP8
    // stack: k3, deleted_child_ptr, bit, node_payload_ptr, level, k0, k1, k2, sibling_ptr, retdest
    %pop8
    // stack: sibling_ptr, retdest
    SWAP1 JUMP

sibling_is_leaf_child_is_non_empty:
    // stack: sibling_ptr, deleted_child_ptr, bit, node_payload_ptr, level, ks, retdest
    POP
    // stack: deleted_child_ptr, node_payload_ptr, bit, retdest
    %jump(insert_child)


global delete_account:
    %stack (address, retdest) -> (address, retdest)
    DUP1 %key_nonce
    // stack: key_nonce, address, retdest
    DUP1 %smt_read_state ISZERO %jumpi(zero_nonce)
    // stack: key_nonce, address, retdest
    DUP1 %smt_delete_state
    // stack: key_nonce, address, retdest
zero_nonce:
    // stack: key_nonce, address, retdest
    POP
    // stack: address, retdest
    DUP1 %key_balance
    // stack: key_balance, address, retdest
    DUP1 %smt_read_state ISZERO %jumpi(zero_balance)
    // stack: key_balance, address, retdest
    DUP1 %smt_delete_state
    // stack: key_balance, address, retdest
zero_balance:
    // stack: key_balance, address, retdest
    POP
    // stack: address, retdest
    DUP1 %key_code
    // stack: key_code, address, retdest
    DUP1 %smt_read_state ISZERO %jumpi(zero_code)
    // stack: key_code, address, retdest
    DUP1 %smt_delete_state
    // stack: key_code, address, retdest
zero_code:
    // stack: key_code, address, retdest
    POP
    // stack: address, retdest
    DUP1 %key_code_length
    // stack: key_code_length, address, retdest
    DUP1 %smt_read_state ISZERO %jumpi(zero_code_length)
    // stack: key_code_length, address, retdest
    DUP1 %smt_delete_state
zero_code_length:
    // N.B.: We don't delete the storage, since there's no way of knowing keys used.
    // stack: key_code_length, address, retdest
    %pop2 JUMP

%macro delete_account
    %stack (address) -> (address, %%after)
    %jump(delete_account)
%%after:
    // stack: (empty)
%endmacro
