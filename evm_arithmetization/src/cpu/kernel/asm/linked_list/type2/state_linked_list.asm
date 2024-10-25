/// The state linked list is stored in SEGMENT_ACCOUNTS_LINKED_LIST in the kernel memory (context=0). 
/// The length of the segment is stored in @GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE.
/// Searching and inserting is done by guessing the predecessor in the list.
/// If the key isn't found in the array, it is inserted 
/// at the correct location. The linked list is used to keep track of
/// inserted, modified and deleted accounts balances, nonces, storage, etc, during the execution, so that the 
/// initial and final MPT state tries can be reconstructed at the end of the execution.
/// An empty astate linked list is written as
/// [@U256_MAX, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST.
/// Each node is encoded using 4 values:
/// - 0: The key
/// - 1: The value
/// - 2: The initial value.
/// - 3: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.

%macro store_initial_state
    PUSH %%after
    %jump(store_initial_state)
%%after:
%endmacro


/// Iterates over the initial state linked list and copies the values in the inital values slot.
/// Computes the length of `SEGMENT_STORAGE_LINKED_LIST` and 
/// checks against `GLOBAL_METADATA_STORAGE_LINKED_LIST_NEXT_AVAILABLE`.
/// It also checks that the next node address is current address + 4
/// and that all keys are strictly increasing.
/// NOTE: It may be more efficient to check that the next node addres != U256_MAX
/// (i.e. node was not deleted) and ensure that no node with repeated key
/// is ever read.
global store_initial_state:
    // stack: retdest
    PUSH @ACCOUNTS_LINKED_LISTS_NODE_SIZE
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    ADD
    // stack: cur_len, retdest
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    DUP1
    MLOAD_GENERAL
    // stack: current_key, current_node_ptr, cur_len, retdest
    %assert_eq_const(@U256_MAX)

    // stack: current_node_ptr, cur_len', retdest
    DUP1
    %next_node
    // stack: next_node_ptr, current_node_ptr, cur_len, retdest
    DUP1
    SWAP2
    %next_initial_node
    %assert_eq(store_initial_state_end) // next_node_ptr == current_node_ptr + node_size
    // stack: next_node_ptr, cur_len', retdest
 
loop_store_initial_state:
    // stack: current_node_ptr, cur_len, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: value, current_node_ptr, cur_len, retdest
    DUP2
    %add_const(@STATE_COPY_PAYLOAD_PTR)
    // stack: cpy_value_ptr, value, current_node_ptr, cur_len, retdest
    SWAP1
    MSTORE_GENERAL // Store cpy_value
    // stack: current_node_ptr, cur_len, retdest
    SWAP1 PUSH @STATE_LINKED_LISTS_NODE_SIZE
    ADD
    SWAP1
    // Check correctness of next node ptr and strict key monotonicity.
    DUP1
    MLOAD_GENERAL
    // stack: current_key, current_node_ptr, cur_len', retdest
    SWAP1
    DUP1
    %next_node
    // stack: next_node_ptr, current_node_ptr, current_key, cur_len', retdest
    DUP1
    SWAP2
    %next_initial_node
    %assert_eq(store_initial_state_end_pop_key) // next_node_ptr ==  current_node_ptr + node_size
    // stack: next_node_ptr, current_key, cur_len', retdest
    SWAP1
    DUP2
    MLOAD_GENERAL
    %assert_gt // next_key > current_key
    // stack: next_node_ptr, cur_len', retdest
    %jump(loop_store_initial_state)

store_initial_state_end_pop_key:
    // stack: next_node_ptr, current_key, cur_len', retdest
    SWAP1 POP

store_initial_state_end:
    // stack: next_node_ptr, cur_len', retdest
    %assert_eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    
    // stack: cur_len, retdest
    DUP1
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    JUMP


// Multiplies the value at the top of the stack, denoted by ptr/4, by 4
// and aborts if ptr/4 >= mem[@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE]/4.
// Also checks that ptr >= @SEGMENT_ACCOUNTS_LINKED_LIST.
// This way, 4*ptr/4 must be pointing to the beginning of a node.
// TODO: Maybe we should check here if the node has been deleted.
%macro get_valid_state_ptr
    // stack: ptr/4
    // Check that the pointer is greater than the segment.
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    DUP2
    %mul_const(4)
    // stack: ptr, @SEGMENT_ACCOUNTS_LINKED_LIST, ptr/4
    %increment %assert_gt
    // stack: ptr/4
    DUP1
    PUSH 4
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    // By construction, both @SEGMENT_ACCOUNTS_LINKED_LIST and the unscaled list len
    // must be multiples of 4
    DIV
    // stack: @SEGMENT_ACCOUNTS_LINKED_LIST/4 + accounts_linked_list_len/4, ptr/4, ptr/4
    %assert_gt
    %mul_const(4)
%endmacro

%macro set_nonce
    // stack: address, nonce
    %key_nonce
    %insert_key
    // stack: (empty)
%endmacro

%macro set_balance
    // stack: address, balance
    %key_balance
    %insert_key
    // stack: (empty)
%endmacro

%macro set_code
    // stack: address, code
    %key_code
    %insert_key
    // stack: (empty)
%endmacro

%macro set_code_length
    // stack: address, code_lenght
    %key_code_length
    %insert_key
    // stack: (empty)
%endmacro


%macro insert_slot
    // stack: addr, slot, value
    %key_storage
    %insert_key
    // stack: (empty)
%endmacro

%macro insert_slot_from_addr_key
    // stack: addr_key, slot_key, value
    %key_storage
    %insert_key
    // stack: (empty)
%endmacro


%macro insert_key
    %stack (key, value) -> (key, value, %%after)
    %jump(insert_key)
    %%after:
%endmacro

/// Inserts the pair `(key, value)`  into the linked list if `key` was not already present,
/// or modifies the vealue if it was already present.
global insert_key:
    // stack: key, value, retdest
    PROVER_INPUT(linked_list::insert_state)
    // stack: pred_ptr/4, key, value, retdest
    %get_valid_state_ptr

    // stack: pred_ptr, key, value, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_key, pred_key, pred_ptr, key, value, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_key)
    // stack: pred_key, pred_ptr, key, value, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, key_found_with_overwrite)
    // The key is not in the list.
    PANIC

key_found_with_overwrite:
    // The key was already in the list
    // stack: pred_ptr, key, value, retdest
    // Load the payload pointer
    %increment
    // stack: payload_ptr_ptr, key, value, retdest
    DUP3 MSTORE_GENERAL
    %pop2
    JUMP

insert_new_key:
    // stack: pred_key, pred_ptr, key, value, retdest
    POP
    // get the value of the next address
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, key, value, retdest
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_key, next_ptr, new_ptr, next_ptr_ptr, key, value, retdest
    DUP5
    // Here, (key > pred_key) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (key < next_key), meaning the new value can be inserted between pred_ptr and next_ptr.
    %assert_lt
    // stack: next_ptr, new_ptr, next_ptr_ptr, key, value, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, key, value, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, key, value, retdest
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, key, value, retdest
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, key, value, retdest
    %add_const(2) // TODO: We're skiping the initial value. This shuould also done with the accounts bc this value should't be used.
    DUP1
    // stack: new_next_ptr, new_next_ptr, next_ptr, key, value, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr, key, value, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    // stack: key, value, retdest
    %pop2
    JUMP


/// Searches the key in the state the linked list. If the key is stored
/// returns the current value of the key, or 0 otherwise. 
global search_key:
    // stack: key, retdest
    PROVER_INPUT(linked_list::search_state)
    // stack: pred_ptr/4, key, retdest
global debug_pred_ptr_p_4:
    %get_valid_state_ptr
global debug_pred_ptr:

    // stack: pred_ptr, key, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_key, pred_key, pred_ptr, key, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // the key was not found.
    %jumpi(key_not_found)
    // stack: pred_key, pred_ptr, key, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
global debug_fail_1:
    %assert_eq
    // stack: pred_ptr, key, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@STATE_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, key_found)
    // The key is not in the list.

global debug_fail_2:
    PANIC

global key_found:
    // The key was already in the list.
    // stack: pred_ptr, key, retdest
    %increment
    MLOAD_GENERAL
    // stack: value, key, retdest
    %stack (value, key, retdest) -> (retdest, value)
    JUMP

key_not_found:
global debug_key_not_found:
    // stack: pred_key, pred_ptr, key, retdest
    %stack (pred_key, pred_ptr, key, retdest) -> (retdest, 0)
global debug_o_margot:
    JUMP

%macro search_key
    %stack (key) -> (key, %%after)
    %jump(search_key)
%%after:
    // stack: value
%endmacro
%macro search_slot_from_addr_key
    // stack: addr_key, slot
    %key_storage
    %search_key
%endmacro

%macro read_balance
    // stack: addr_key
    %key_balance
    %search_key
%endmacro

%macro read_code
    // stack: addr_key
    %key_code
    %search_key
    // stack: code_hash
%endmacro

%macro read_code_length
    // stack: addr_key
    %key_code_length
    %search_key
    // stack: code_length
%endmacro

%macro read_nonce
    // stack: addr_key
    %key_nonce
    %search_key
    // stack: nonce
%endmacro

%macro remove_key
    PUSH %%after
    SWAP1
    %jump(remove_key)
%%after:
%endmacro

%macro remove_balance
    %key_balance
    %remove_key
%endmacro

%macro remove_slot_from_addr
    %key_storage
    %remove_key
%endmacro

/// Removes the key and its value from the state linked list.
/// Panics if the key is not in the list.
global remove_key:
    // stack: key, retdest
    PROVER_INPUT(linked_list::remove_state)
    // stack: pred_ptr/4, key, retdest
    %get_valid_state_ptr
    // stack: pred_ptr, key, retdest
    %add_const(@STATE_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr,  key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_key, next_ptr, next_ptr_ptr, key, retdest
    DUP4
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, key, retdest
    %add_const(@STATE_NEXT_NODE_PTR)
    // stack: next_next_ptr_ptr, next_ptr_ptr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, key, retdest
    SWAP1
    %mstore_u256_max
    // stack: next_next_ptr, next_ptr_ptr, key, retdest
    MSTORE_GENERAL
    POP
    JUMP

%macro read_slot_from_current_addr
    // stack: slot
    %address
    %key_storage
    %stack (storage_key) -> (storage_key, %%after)
    // stack: storage_key, %%after
    %jump(search_key)
%%after:
    // stack: slot_value
%endmacro

%macro read_slot_from_addr_key
    // stack: state_key, slot
    %key_storage
    %stack (storage_key) -> (storage_key, %%after)
    %jump(search_key)
%%after:
    // stack: slot_value
%endmacro

%macro read_slot_from_addr
    // stack: address, slot
    %addr_to_state_key
    %key_storage
    %stack (storage_key) -> (storage_key, %%after)
    // stack: storage_key, %%after
    %jump(search_key)
%%after:
    // stack: slot_value
%endmacro

%macro first_node
    // stack: empty
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_node
%endmacro

%macro first_initial_node
    // stack: empty
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_initial_node
%endmacro

%macro next_node
    // stack: node_ptr
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    MLOAD_GENERAL
    // stack: next_node_ptr
%endmacro

%macro next_initial_node
    // stack: node_ptr
    %add_const(@ACCOUNTS_LINKED_LISTS_NODE_SIZE)
    // stack: next_node_ptr
%endmacro