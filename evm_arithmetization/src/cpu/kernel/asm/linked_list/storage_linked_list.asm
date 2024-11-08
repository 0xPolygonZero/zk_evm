/// The storage linked list is stored in SEGMENT_STORAGE_LINKED_LIST in the kernel memory (context=0).
/// The length of the segment is stored in GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE.
/// Searching and inserting is done by guessing the predecessor in the list.
/// If the storage key isn't found in the array, it is inserted 
/// at the correct location. This linked list is used to keep track of
/// inserted and deleted slots during the execution, so that the 
/// initial and final MPT state tries can be reconstructed at the end of the execution.
/// An empty storage linked list is written as
/// [@U256_MAX, _, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST.
/// Each slot is encoded using 5 values:
/// - 0: The account key
/// - 1: The slot key
/// - 2: The slot value.
/// - 3: The initial slot value.
/// - 4: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.

%macro store_initial_slots
    PUSH %%after
    %jump(store_initial_slots)
%%after:
%endmacro


/// Iterates over the initial storage linked list and copies the slots values into
/// the initial values.
/// Computes the length of `SEGMENT_STORAGE_LINKED_LIST` and 
/// checks against `GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE`.
/// It also checks that the next node address is current address + 5
/// and that all keys are strictly increasing.
/// NOTE: It may be more efficient to check that the next node addres != U256_MAX
/// (i.e. node was not deleted) and ensure that no node with repeated key
/// is ever read.
global store_initial_slots:
    // stack: retdest
    PUSH @STORAGE_LINKED_LISTS_NODE_SIZE
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    ADD
    // stack: cur_len, retdest
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    DUP1
    MLOAD_GENERAL
    // stack: current_addr_key, current_node_ptr, cur_len, retdest
    %assert_eq_const(@U256_MAX)

    // stack: current_node_ptr, cur_len', retdest
    DUP1
    %next_slot
    // stack: next_node_ptr, current_node_ptr, cur_len, retdest
    DUP1
    SWAP2
    %next_initial_slot
    %assert_eq(store_initial_slots_end) // next_node_ptr == current_node_ptr + node_size
    // stack: next_node_ptr, cur_len', retdest
 
loop_store_initial_slots:
    // stack: current_node_ptr, cur_len, retdest
    DUP1
    %add_const(2)
    MLOAD_GENERAL
    // stack: value, current_node_ptr, cur_len, retdest
    DUP2
    %add_const(@STORAGE_COPY_PAYLOAD_PTR)
    // stack: cpy_value_ptr, value, current_node_ptr, cur_len, retdest
    SWAP1
    MSTORE_GENERAL // Store cpy_value
    // stack: current_node_ptr, cur_len, retdest
    SWAP1 PUSH @STORAGE_LINKED_LISTS_NODE_SIZE
    ADD
    SWAP1
    // Check correctness of next node ptr and strict key monotonicity.
    DUP1
    MLOAD_GENERAL
    // stack: current_addr_key, current_node_ptr, cur_len', retdest
    SWAP1
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: current_slot_key, current_node_ptr, current_addr_key, cur_len', retdest
    SWAP1
    DUP1
    %next_slot
    // stack: next_node_ptr, current_node_ptr, current_slot_key, current_addr_key, cur_len', retdest
    DUP1
    SWAP2
    %next_initial_slot
    %assert_eq(store_initial_slots_end_pop_keys) // next_node_ptr == current_node_ptr + node_size
    // stack: next_node_ptr, current_slot_key, current_addr_key, cur_len', retdest
    DUP1
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_node_slot_key, next_node_ptr, next_node_ptr, current_slot_key, current_addr_key, cur_len', retdest
    SWAP1
    MLOAD_GENERAL
    // stack: next_node_addr_key, next_node_slot_key, next_node_ptr, current_slot_key, current_addr_key, cur_len', retdest
    SWAP3
    LT
    // stack: current_slot_key > next_node_slot_key, next_node_ptr, next_node_addr_key, current_addr_key, cur_len', retdest
    SWAP2
    SWAP1
    SWAP3
    // stack: current_addr_key, next_node_addr_key, current_slot_key > next_node_slot_key, next_node_ptr, cur_len', retdest
    DUP2
    DUP2
    EQ
    // stack: current_addr_key == next_node_addr_key, current_addr_key, next_node_addr_key, current_slot_key > next_node_slot_key, next_node_ptr, cur_len', retdest
    SWAP1
    SWAP3
    MUL // AND
    // stack  current_slot_key > next_node_slot_key AND current_addr_key == next_node_addr_key, next_node_addr_key, current_addr_key, next_node_ptr, cur_len', retdest
    SWAP2
    LT
    ADD // OR
    %assert_nonzero
    %jump(loop_store_initial_slots)

store_initial_slots_end_pop_keys:
    // stack: next_node_ptr, current_slot_key, current_addr_key, cur_len', retdest
    SWAP2
    %pop2

store_initial_slots_end:
    // stack: next_node_ptr, cur_len', retdest
    %assert_eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    
    // stack: cur_len, retdest
    DUP1
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_STORAGE_LINKED_LIST_LEN)
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE)
    JUMP


// Multiplies the value at the top of the stack, denoted by ptr/5, by 5
// and aborts if ptr/5 >= (mem[@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE] - @SEGMENT_STORAGE_LINKED_LIST)/5.
// This way, @SEGMENT_STORAGE_LINKED_LIST + 5*ptr/5 must be pointing to the beginning of a node.
// TODO: Maybe we should check here if the node has been deleted.
%macro get_valid_slot_ptr
    // stack: ptr/5
    DUP1
    PUSH 5
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    // stack: segment, 5, ptr/5, ptr/5
    %mload_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE)
    SUB
    // stack: accessed_strg_keys_len, 5, ptr/5, ptr/5
    // By construction, the unscaled list len must be multiple of 5
    DIV
    // stack: accessed_strg_keys_len/5, ptr/5, ptr/5
    %assert_gt
    %mul_const(5)
    %add_const(@SEGMENT_STORAGE_LINKED_LIST)
%endmacro

/// Inserts the pair (address_key, storage_key) and a new payload pointer into the linked list if it is not already present,
/// or modifies its payload if it was already present.
global insert_slot:
    // stack: addr_key, key, value, retdest
    PROVER_INPUT(linked_list::insert_slot)
    // stack: pred_ptr/5, addr_key, key, value, retdest
    %get_valid_slot_ptr

    // stack: pred_ptr, addr_key, key, value, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr_key, pred_addr_key, pred_ptr, addr_key, key, value, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_slot)
    // stack: pred_addr_key, pred_ptr, addr_key, key, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr_key, key, value, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: pred_key, pred_ptr, addr_key, key, value, retdest
    DUP1 DUP5
    GT
    %jumpi(insert_new_slot)
    // stack: pred_key, pred_ptr, addr_key, key, value, retdest
    DUP4
    // We know that key <= pred_key. It must hold that pred_key == key.
    %assert_eq
    
    // stack: pred_ptr, addr_key, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@STORAGE_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, slot_found_write_value)
    // The storage key is not in the list.
    PANIC

insert_new_slot:
    // stack: pred_addr or pred_key, pred_ptr, addr_key, key, value, retdest
    POP
    // get the value of the next address
    %add_const(@STORAGE_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, addr_key, key, value, retdest
    %mload_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_addr_key, next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    DUP1
    DUP6
    // Here, (addr_key > pred_addr_key) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (addr_key < next_addr_key), meaning the new value can be inserted between pred_ptr and next_ptr.
    LT
    %jumpi(next_node_ok)
    // If addr_key <= next_addr_key, then it addr must be equal to next_addr
    // stack: next_addr_key, next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    DUP5
    %assert_eq
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    DUP1 // This is added just to have the correct stack in next_node_ok
    DUP7
    // The next key must be strictly larger
    %assert_lt

next_node_ok:
    // stack: next_addr or next_key, next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    POP
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr_key, key, value, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, addr_key, key, value, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr_key, key, value, retdest
    // Write the address in the new node
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr_key, key, value, retdest
    // Write the key in the new node
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, addr_key, key, value, retdest
    // Write the value in the linked list.
    %increment
    DUP1 %increment
    // stack: new_ptr+3, new_value_ptr, next_ptr, addr_key, key, value, retdest
    %stack (new_cloned_value_ptr, new_value_ptr, next_ptr, addr_key, key, value, retdest)
        -> (value, new_cloned_value_ptr, value, new_value_ptr, new_cloned_value_ptr, next_ptr, retdest)
    MSTORE_GENERAL // Store copied value.
    MSTORE_GENERAL // Store value.

    // stack: new_ptr + 3, next_ptr, retdest
    %increment
    DUP1
    // stack: new_next_ptr_ptr, new_next_ptr_ptr, next_ptr, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr_ptr, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE)
    // stack: retdest
    JUMP

slot_found_write_value:
    // stack: pred_ptr, addr_key, key, value, retdest
    %add_const(2)
    %stack (payload_ptr, addr_key, key, value) -> (value, payload_ptr)
    MSTORE_GENERAL
    // stack: retdest
    JUMP

%macro insert_slot
    // stack: addr, slot, value
    %addr_to_state_key
    SWAP1
    %slot_to_storage_key
    %stack (slot_key, addr_key, value) -> (addr_key, slot_key, value, %%after)
    %jump(insert_slot)
%%after:
    // stack: (empty)
%endmacro

%macro insert_slot_from_addr_key
    // stack: addr_key, slot_key, value
    SWAP1
    %slot_to_storage_key
    %stack (slot_key, addr_key, value) -> (addr_key, slot_key, value, %%after)
    %jump(insert_slot)
%%after:
    // stack: (empty)
%endmacro


%macro search_slot_from_addr_key
    // stack: state_key, slot
    SWAP1
    %slot_to_storage_key
    %stack (storage_key, state_key) -> (state_key, storage_key, %%after)
    %jump(search_slot)
%%after:
%endmacro

/// Searches the pair (address_key, storage_key) in the storage the linked list.
/// Returns 0 if the storage key was inserted, or the current `value` if it was already present.
global search_slot:
    // stack: addr_key, key, retdest
    PROVER_INPUT(linked_list::search_slot)
    // stack: pred_ptr/5, addr_key, key, retdest
    %get_valid_slot_ptr

    // stack: pred_ptr, addr_key, key, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr_key, pred_addr_key, pred_ptr, addr_key, key, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // the slot was not found
    %jumpi(slot_not_found)
    // stack: pred_addr_key, pred_ptr, addr_key, key, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr_key, key, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: pred_key, pred_ptr, addr_key, key, retdest
    DUP1 DUP5
    GT
    %jumpi(slot_not_found)
    // stack: pred_key, pred_ptr, addr_key, key, retdest
    DUP4
    // We know that key <= pred_key. It must hold that pred_key == key.
    %assert_eq
    // stack: pred_ptr, addr_key, key, retdest
    
    // stack: pred_ptr, addr_key, key, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@STORAGE_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, slot_found_no_write)
    // The storage key is not in the list.
    PANIC
slot_not_found:    
    // stack: pred_addr_or_pred_key, pred_ptr, addr_key, key, retdest
    %stack (pred_addr_or_pred_key, pred_ptr, addr_key, key, retdest)
        -> (retdest, 0)
    JUMP

slot_found_no_write:
    // The slot was already in the list
    // stack: pred_ptr, addr_key, key, retdest
    // Load the old value
    %add_const(2)
    MLOAD_GENERAL
    // stack: old_value, addr_key, key, retdest
    %stack (old_value, addr_key, key, retdest) -> (retdest, old_value)
    JUMP

/// Removes the storage key and its value from the list.
/// Panics if the key is not in the list.
global remove_slot:
    // stack: addr_key, key, retdest
    PROVER_INPUT(linked_list::remove_slot)
    // stack: pred_ptr/5, addr_key, key, retdest
    %get_valid_slot_ptr
    // stack: pred_ptr, addr_key, key, retdest
    %add_const(@STORAGE_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, addr_key, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr, addr_key, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_addr_key, next_ptr, next_ptr_ptr, addr_key, key, retdest
    DUP4
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr_key, key, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, next_ptr_ptr, addr_key, key, retdest
    DUP5
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr_key, key, retdest
    %add_const(@STORAGE_NEXT_NODE_PTR)
    // stack: next_next_ptr_ptr, next_ptr_ptr, addr_key, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, addr_key, key, retdest
    // Mark the next node as deleted
    SWAP1
    %mstore_u256_max
    // stack: next_next_ptr, next_ptr_ptr, addr_key, key, retdest
    MSTORE_GENERAL
    %pop2
    JUMP

%macro remove_slot_from_addr_key
    // stack: addr_key, slot
    SWAP1
    %slot_to_storage_key
    %stack (key, addr_key) -> (addr_key, key, %%after)
    %jump(remove_slot)
%%after:
%endmacro

%macro remove_slot_from_addr
    // stack: addr, slot
    %addr_to_state_key
    SWAP1
    %slot_to_storage_key
    %stack (key, addr_key) -> (addr_key, key, %%after)
    %jump(remove_slot)
%%after:
%endmacro

%macro read_slot_from_current_addr
    // stack: slot
    %slot_to_storage_key
    %stack (storage_key) -> (storage_key, %%after)
    %address
    %addr_to_state_key
    // stack: addr_key, storage_key,  %%after
    %jump(search_slot)
%%after:
    // stack: slot_value
%endmacro

%macro read_slot_from_addr
    // stack: address, slot
    SWAP1
    %slot_to_storage_key
    %stack (storage_key, address) -> (address, storage_key, %%after)
    %addr_to_state_key
    // stack: addr_key, storage_key, %%after
    %jump(search_slot)
%%after:
    // stack: slot_value
%endmacro

%macro read_slot_from_addr_key
    // stack: state_key, slot
    SWAP1
    %slot_to_storage_key
    %stack (storage_key, state_key) -> (state_key, storage_key, %%after)
    %jump(search_slot)
%%after:
    // stack: slot_ptr
%endmacro

%macro first_slot
    // stack: empty
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %next_slot
%endmacro

%macro first_initial_slot
    // stack: empty
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %next_initial_slot
%endmacro

%macro next_slot
    // stack: node_ptr
    %add_const(@STORAGE_NEXT_NODE_PTR)
    MLOAD_GENERAL
    // stack: next_node_ptr
%endmacro

%macro next_initial_slot
    // stack: node_ptr
    %add_const(@STORAGE_LINKED_LISTS_NODE_SIZE)
    // stack: next_node_ptr
%endmacro