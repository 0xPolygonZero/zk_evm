/// The accounts linked list is stored in SEGMENT_ACCOUNTS_LINKED_LIST in the kernel memory (context=0). 
/// The length of the segment is stored in @GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE.
/// Searching and inserting is done by guessing the predecessor in the list.
/// If the address key isn't found in the array, it is inserted 
/// at the correct location. The linked lists are used to keep track of
/// inserted, modified and deleted accounts during the execution, so that the 
/// initial and final MPT state tries can be reconstructed at the end of the execution.
/// An empty account linked list is written as
/// [@U256_MAX, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST.
/// Each account is encoded using 4 values:
/// - 0: The account key
/// - 1: A ptr to the payload (the account values)
/// - 2: A ptr to the initial payload.
/// - 3: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.

%macro store_initial_accounts
    PUSH %%after
    %jump(store_initial_accounts)
%%after:
%endmacro

/// Iterates over the initial account linked list and shallow copies
/// the accounts, storing a pointer to the copied account in the node.
/// Computes the length of `SEGMENT_ACCOUNTS_LINKED_LIST` and 
/// stores it in `GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE`.
/// It also checks that the next node address is current address + 4
/// and that all keys are strictly increasing.
/// NOTE: It may be more efficient to check that the next node addres != U256_MAX
/// (i.e. node was not deleted) and ensure that no node with repeated key
/// is ever read.
global store_initial_accounts:
    // stack: retdest
    PUSH @ACCOUNTS_LINKED_LISTS_NODE_SIZE
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    ADD
    // stack: cur_len, retdest
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    // stack: current_node_ptr, cur_len, retdest
    DUP1
    MLOAD_GENERAL
    // stack: current_addr_key, current_node_ptr, cur_len', retdest
    %assert_eq_const(@U256_MAX)
    DUP1
    %next_account
    // stack: next_node_ptr, current_node_ptr, cur_len', retdest
    DUP1
    SWAP2
    %next_initial_account
    %assert_eq(store_initial_accounts_end) // next_node_ptr ==  current_node_ptr + node_size
    // stack: next_node_ptr, cur_len', retdest
    
loop_store_initial_accounts:
    // stack: current_node_ptr, cur_len, retdest
    %get_trie_data_size
    // stack: cpy_ptr, current_node_ptr, cur_len, retdest
    DUP2
    %increment
    MLOAD_GENERAL
    // stack: nonce_ptr, cpy_ptr, current_node_ptr, cur_len, retdest
    DUP1
    %mload_trie_data // nonce
    %append_to_trie_data
    %increment
    // stack: balance_ptr, cpy_ptr, current_node_ptr, cur_len, retdest
    DUP1
    %mload_trie_data // balance
    %append_to_trie_data
    %increment // The storage_root_ptr is not really necessary
    // stack: storage_root_ptr_ptr, cpy_ptr, current_node_ptr, cur_len, retdest
    DUP1
    %mload_trie_data // storage_root_ptr
    %append_to_trie_data
    %increment
    // stack: code_hash_ptr, cpy_ptr, current_node_ptr, cur_len, retdest
    %mload_trie_data // code_hash
    %append_to_trie_data
    // stack: cpy_ptr, current_node_ptr, cur_len, retdest
    DUP2
    %add_const(2)
    SWAP1
    MSTORE_GENERAL // Store cpy_ptr
    // stack: current_node_ptr, cur_len, retdest
    SWAP1 PUSH @ACCOUNTS_LINKED_LISTS_NODE_SIZE 
    ADD
    SWAP1
    // Check next node ptr validity and strict keys monotonicity
    DUP1
    MLOAD_GENERAL
    // stack: current_addr_key, current_node_ptr, cur_len', retdest
    SWAP1
    DUP1
    %next_account
    // stack: next_node_ptr, current_node_ptr, current_addr_key, cur_len', retdest
    DUP1
    SWAP2
    %next_initial_account
    %assert_eq(store_initial_accounts_end_pop_key) // next_node_ptr ==  current_node_ptr + node_size
    // stack: next_node_ptr, current_addr_key, cur_len', retdest
    SWAP1
    DUP2
    MLOAD_GENERAL
    %assert_gt // next_addr_key > current_addr_key
    // stack: next_node_ptr, cur_len', retdest
    %jump(loop_store_initial_accounts)

store_initial_accounts_end_pop_key:
    // stack: next_node_ptr, current_addr_key, cur_len', retdest
    SWAP1 POP
store_initial_accounts_end:
    // stack: next_node_ptr, cur_len', retdest
    %assert_eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    // stack: cur_len, retdest
    DUP1
    %mstore_global_metadata(@GLOBAL_METADATA_INITIAL_ACCOUNTS_LINKED_LIST_LEN)
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    JUMP

%macro insert_account_with_overwrite
    %stack (addr_key, ptr) -> (addr_key, ptr, %%after)
    %jump(insert_account_with_overwrite)
%%after:
%endmacro

// Multiplies the value at the top of the stack, denoted by ptr/4, by 4
// and aborts if ptr/4 >= mem[@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE]/4.
// Also checks that ptr >= @SEGMENT_ACCOUNTS_LINKED_LIST.
// This way, 4*ptr/4 must be pointing to the beginning of a node.
// TODO: Maybe we should check here if the node has been deleted.
%macro get_valid_account_ptr
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

global insert_account_with_overwrite:
    // stack: addr_key, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_account)
    // stack: pred_ptr/4, addr_key, payload_ptr, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr_key, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr_key, pred_addr_key, pred_ptr, addr_key, payload_ptr, retdest
    DUP4 GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_account)
    // stack: pred_addr_key, pred_ptr, addr_key, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    
    // stack: pred_ptr, addr_key, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, account_found_with_overwrite)
    // The storage key is not in the list.
    PANIC

account_found_with_overwrite:
    // The address was already in the list
    // stack: pred_ptr, addr_key, payload_ptr, retdest
    // Load the payload pointer
    %increment
    // stack: payload_ptr_ptr, addr_key, payload_ptr, retdest
    DUP3 MSTORE_GENERAL
    %pop2
    JUMP

insert_new_account:
    // stack: pred_addr_key, pred_ptr, addr_key, payload_ptr, retdest
    POP
    // get the value of the next address
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, addr_key, payload_ptr, retdest
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr_key, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_addr_key, next_ptr, new_ptr, next_ptr_ptr, addr_key, payload_ptr, retdest
    DUP5
    // Here, (addr_key > pred_addr_key) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (addr_key < next_addr_key), meaning the new value can be inserted between pred_ptr and next_ptr.
    %assert_lt
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr_key, payload_ptr, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, addr_key, payload_ptr, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr_key, payload_ptr, retdest
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr_key, payload_ptr, retdest
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, addr_key, payload_ptr, retdest
    %increment
    DUP1
    DUP5
    %clone_account
    MSTORE_GENERAL
    %increment
    DUP1
    // stack: new_next_ptr, new_next_ptr, next_ptr, addr_key, payload_ptr, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr, addr_key, payload_ptr, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    // stack: addr_key, payload_ptr, retdest
    %pop2
    JUMP


/// Searches the account addr in the linked list.
/// Returns 0 if the account was not found or `original_ptr` if it was already present.
global search_account:
    // stack: addr_key, retdest
    PROVER_INPUT(linked_list::search_account)
    // stack: pred_ptr/4, addr_key, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr_key, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr_key, pred_addr_key, pred_ptr, addr_key, retdest
    DUP4 GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(account_not_found)
    // stack: pred_addr_key, pred_ptr, addr_key, retdest
    // If we are here we know that addr_key <= pred_addr_key. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    
    // stack: pred_ptr, addr_key, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, account_found)
    // The storage key is not in the list.
    PANIC

account_found:
    // The address was already in the list
    // stack: pred_ptr, addr_key, retdest
    // Load the payload pointer
    %increment
    MLOAD_GENERAL
    // stack: orig_payload_ptr, addr_key, retdest
    %stack (orig_payload_ptr, addr_key, retdest) -> (retdest, orig_payload_ptr)
    JUMP

account_not_found:
    // stack: pred_addr_key, pred_ptr, addr_key, retdest
    %stack (pred_addr_key, pred_ptr, addr_key, retdest) -> (retdest, 0)
    JUMP

%macro remove_account_from_linked_list
    PUSH %%after
    SWAP1
    %jump(remove_account)
%%after:
%endmacro

/// Removes the address and its value from the access list.
/// Panics if the key is not in the list.
global remove_account:
    // stack: addr_key, retdest
    PROVER_INPUT(linked_list::remove_account)
    // stack: pred_ptr/4, addr_key, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr_key, retdest
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    // stack: next_ptr_ptr, addr_key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr, addr_key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_addr_key, next_ptr, next_ptr_ptr, addr_key, retdest
    DUP4
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr_key, retdest
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    // stack: next_next_ptr_ptr, next_ptr_ptr, addr_key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, addr_key, retdest
    SWAP1
    %mstore_u256_max
    // stack: next_next_ptr, next_ptr_ptr, addr_key, retdest
    MSTORE_GENERAL
    POP
    JUMP

/// Called when an account is deleted: it deletes all slots associated with the account.
global remove_all_account_slots:
    // stack: addr_key, retdest
    PROVER_INPUT(linked_list::remove_address_slots)
    // pred_ptr/5, retdest
    %get_valid_slot_ptr
    // stack: pred_ptr, addr_key, retdest
    // First, check that the previous address is not `addr`
    DUP1 MLOAD_GENERAL
    // stack: pred_addr_key, pred_ptr, addr_key, retdest
    DUP3 EQ %jumpi(panic)
    // stack: pred_ptr, addr_key, retdest
    DUP1

// Now, while the next address is `addr`, remove the next slot.
remove_all_slots_loop:
    // stack: pred_ptr, pred_ptr, addr_key, retdest
    %add_const(@STORAGE_NEXT_NODE_PTR) DUP1 MLOAD_GENERAL
    // stack: cur_ptr, cur_ptr_ptr, pred_ptr, addr_key, retdest
    DUP1 %eq_const(@U256_MAX) %jumpi(remove_all_slots_end)
    DUP1 %add_const(@STORAGE_NEXT_NODE_PTR) MLOAD_GENERAL 
    // stack: next_ptr, cur_ptr, cur_ptr_ptr, pred_ptr, addr_key, retdest
    SWAP1 DUP1
    // stack: cur_ptr, cur_ptr, next_ptr, cur_ptr_ptr, pred_ptr, addr_key, retdest
    MLOAD_GENERAL
    DUP6 EQ ISZERO %jumpi(remove_all_slots_pop_and_end)
    
    // Remove slot: update the value in cur_ptr_ptr, and set cur_ptr+4 to @U256_MAX.
    // stack: cur_ptr, next_ptr, cur_ptr_ptr, pred_ptr, addr_key, retdest
    SWAP2 SWAP1
    // stack: next_ptr, cur_ptr_ptr, cur_ptr, pred_ptr, addr_key, retdest
    MSTORE_GENERAL
    // stack: cur_ptr, pred_ptr, addr_key, retdest
    %add_const(@STORAGE_NEXT_NODE_PTR) 
    %mstore_u256_max
    // stack: pred_ptr, addr_key, retdest
    DUP1
    %jump(remove_all_slots_loop)

remove_all_slots_pop_and_end:
    POP
remove_all_slots_end:
    // stack: next_ptr, cur_ptr_ptr, pred_ptr, addr_key, retdest
    %pop4 JUMP

%macro remove_all_account_slots
    %stack (addr_key) -> (addr_key, %%after)
    %jump(remove_all_account_slots)
%%after:
%endmacro

%macro read_account_from_addr
    %stack (addr) -> (addr, %%after)
    %addr_to_state_key
    %jump(search_account)
%%after:
    // stack: account_ptr
%endmacro

%macro nonce_from_ptr
    %mload_trie_data
%endmacro

%macro balance_from_ptr
    %increment
    %mload_trie_data
%endmacro

%macro first_account
    // stack: empty
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_account
%endmacro

%macro first_initial_account
    // stack: empty
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_initial_account
%endmacro

%macro next_account
    // stack: node_ptr
    %add_const(@ACCOUNTS_NEXT_NODE_PTR)
    MLOAD_GENERAL
    // stack: next_node_ptr
%endmacro

%macro next_initial_account
    // stack: node_ptr
    %add_const(@ACCOUNTS_LINKED_LISTS_NODE_SIZE)
    // stack: next_node_ptr
%endmacro