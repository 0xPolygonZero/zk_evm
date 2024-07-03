/// Access lists for addresses and storage keys.
/// The access list is stored in a sorted linked list in SEGMENT_ACCESSED_ADDRESSES for addresses and
/// SEGMENT_ACCESSED_STORAGE_KEYS segment for storage keys. The length of
/// the segments is stored in the global metadata.
/// Both arrays are stored in the kernel memory (context=0).
/// Searching and inserting is done by guessing the predecessor in the list.
/// If the address/storage key isn't found in the array, it is inserted at the end.

// Initialize an empty account linked list (@U256_MAX)⮌
// which is written as [@U256_MAX, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST
// The values at the respective positions are:
// - 0: The account key
// - 1: A ptr to the payload (the account values)
// - 2: A ptr to the intial payload.
// - 3: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.
// Initialize also an empty storage linked list (@U256_MAX)⮌
// which is written as [@U256_MAX, _, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST
// The values at the respective positions are:
// - 0: The account key
// - 1: The key
// - 2: A ptr to the payload (the stored value)
// - 3: A ptr to the inital payload.
// - 4: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.
global init_linked_lists:
    // stack: (empty)

    // Initialize SEGMENT_ACCOUNTS_LINKED_LIST
    // Store @U256_MAX at the beggining of the segment
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST // ctx == virt == 0
    DUP1
    PUSH @U256_MAX
    MSTORE_GENERAL
    // Store @SEGMENT_ACCOUNTS_LINKED_LIST at address 2
    %add_const(3)
    DUP1
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    MSTORE_GENERAL
    
    // Store the segment scaled length
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)

    // Initialize SEGMENT_STORAGE_LINKED_LIST
    // Store @U256_MAX at the beggining of the segment
    PUSH @SEGMENT_STORAGE_LINKED_LIST // ctx == virt == 0
    DUP1
    PUSH @U256_MAX
    MSTORE_GENERAL
    // Store @SEGMENT_ACCOUNTS_LINKED_LIST at address 2
    %add_const(4)
    DUP1
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    MSTORE_GENERAL
    
    // Store the segment scaled length
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    JUMP

%macro init_linked_lists
    PUSH %%after
    %jump(init_account_linked_lists)
%%after:
%endmacro

%macro store_initial_accounts
    PUSH %%after
    %jump(store_initial_accounts)
%%after:
%endmacro

/// Iterates over the inital account linked list and shallow copies
/// the accounts, storing a pointer to the copied account in the node.
global store_initial_accounts:
    // stack: retdest

    PUSH  @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_account
loop_store_initial_accounts:
    // stack: current_node_ptr
    %get_trie_data_size
    DUP2
    MLOAD_GENERAL
    // stack: current_addr, cpy_ptr, current_node_ptr, retdest
    %eq_const(@U256_MAX)
    %jumpi(store_initial_accounts_end)
    DUP2
    %increment
    MLOAD_GENERAL
    // stack: nonce_ptr, cpy_ptr, current_node_ptr, retdest
    DUP1
    %mload_trie_data // nonce
global debug_storing_nonce:
    %append_to_trie_data
    %increment
    // stack: balance_ptr, cpy_ptr, current_node_ptr, retdest
    DUP1
    %mload_trie_data // balance
global debug_storing_balance:
    %append_to_trie_data
    %increment // The storage_root_ptr is not really necessary
    // stack: storage_root_ptr_ptr, cpy_ptr, current_node_ptr, retdest
    DUP1
    %mload_trie_data // storage_root_ptr
    %append_to_trie_data
    %increment
    // stack: code_hash_ptr, cpy_ptr, current_node_ptr, retdest
global debug_loading_code_hash:
    %mload_trie_data // code_hash
global debug_code_hash:
    %append_to_trie_data
    // stack: cpy_ptr, current_node_ptr, retdest
    DUP2
    %add_const(2)
    SWAP1
global debug_store_account_cpy_ptr:
    MSTORE_GENERAL // Store cpy_ptr
    %next_account
    %jump(loop_store_initial_accounts)

store_initial_accounts_end:
    %pop2
    JUMP


%macro insert_account_to_linked_list
    %stack (addr, ptr) -> (addr, ptr, %%after)
    %jump(insert_account_to_linked_list)
%%after:
    // stack: cold_access
%endmacro

%macro insert_account_with_overwrite
    %stack (addr, ptr) -> (addr, ptr, %%after)
    %jump(insert_account_with_overwrite)
%%after:
    // stack: cold_access
%endmacro

%macro insert_account_to_linked_list_no_return
    %insert_account_to_linked_list
    %pop2
%endmacro

%macro insert_account_with_overwrite_no_return
    %insert_account_with_overwrite
    %pop2
%endmacro

// Multiply the value at the top of the stack, denoted by ptr/4, by 4
// and abort if ptr/4 >= mem[@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN]/4
// In this way 4*ptr/4 must be pointing to the beginning of a node.
// TODO: Maybe we should check here if the node have been deleted.
%macro get_valid_account_ptr
     // stack: ptr/4
    DUP1
    PUSH 4
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)
    // By construction, both @SEGMENT_ACCESSED_STORAGE_KEYS and the unscaled list len
    // must be multiples of 4
    DIV
    // stack: @SEGMENT_ACCESSED_STORAGE_KEYS/4 + accessed_strg_keys_len/4, ptr/4, ptr/4
    %assert_gt
    %mul_const(4)
%endmacro

/// Inserts the account addr and payload pointer into the linked list if it is not already present.
/// Return `1, payload_ptr` if the account was inserted, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
global insert_account_to_linked_list:
    // stack: addr, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_account)
    // stack: pred_ptr/4, addr, payload_ptr, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, payload_ptr, retdest
    DUP4 GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_account)
    // stack: pred_addr, pred_ptr, addr, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, payload_ptr, retdest
    
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(3)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, account_found)
    // The storage key is not in the list.
    PANIC
global account_found:
    // The address was already in the list
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Load the the payload pointer and access counter
    %increment
    MLOAD_GENERAL
    // stack: orig_payload_ptr, addr, payload_ptr, retdest
    // TODO: Remove the now unused cold_access
    %stack (orig_payload_ptr, addr, payload_ptr, retdest) -> (retdest, 0, orig_payload_ptr)
    JUMP
//DEBUG
global insert_new_account:
    // stack: pred_addr, pred_ptr, addr, payload_ptr, retdest
    POP
    // get the value of the next address
    %add_const(3)
    // stack: next_ptr_ptr, addr, payload_ptr, retdest
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_addr, next_ptr, new_ptr, next_ptr_ptr, addr, payload_ptr, retdest
    DUP5
    // Here, (addr > pred_addr) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (addr < next_addr), meaning the new value can be inserted between pred_ptr and next_ptr.
    %assert_lt
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, payload_ptr, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, addr, payload_ptr, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, payload_ptr, retdest
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, payload_ptr, retdest
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, addr, payload_ptr, retdest
    %increment
    DUP1
    DUP5
    %clone_account
    MSTORE_GENERAL
    %increment
    DUP1
    // stack: new_next_ptr, new_next_ptr, next_ptr, addr, payload_ptr, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr, addr, payload_ptr, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)
    // stack: addr, payload_ptr, retdest
    // TODO: Don't for get to %journal_add_account_loaded
    %stack (addr, payload_ptr, retdest) -> (retdest, 0, payload_ptr)
    JUMP

global insert_account_with_overwrite:
    // stack: addr, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_account)
    // stack: pred_ptr/4, addr, payload_ptr, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, payload_ptr, retdest
    DUP4 GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_account)
    // stack: pred_addr, pred_ptr, addr, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, payload_ptr, retdest
    
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(3)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, account_found_with_overwrite)
    // The storage key is not in the list.
    PANIC

account_found_with_overwrite:
    // The address was already in the list
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Load the the payload pointer and access counter
    %increment
    // stack: payload_ptr_ptr, addr, payload_ptr, retdest
    DUP3 MSTORE_GENERAL
    %stack (addr, payload_ptr, retdest) -> (retdest, 0, payload_ptr)
    JUMP

%macro search_account
    %stack (addr, ptr) -> (addr, ptr, %%after)
    %jump(search_account)
%%after:
    // stack: cold_access
%endmacro

%macro search_account_no_return
    %search_account
    %pop2
%endmacro


/// Search the account addr andin the linked list.
/// Return `1, payload_ptr` if the account was not found, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
global search_account:
    // stack: addr, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_account)
    // stack: pred_ptr/4, addr, payload_ptr, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, payload_ptr, retdest
    DUP4 GT
    DUP3 %eq_const(@SEGMENT_ACCOUNTS_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(account_not_found)
    // stack: pred_addr, pred_ptr, addr, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, payload_ptr, retdest
    
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(3)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, account_found)
    // The storage key is not in the list.
    PANIC

account_not_found:
    // stack: pred_addr, pred_ptr, addr, payload_ptr, retdest
    %pop3
    SWAP1
    PUSH 1
    SWAP1
    JUMP

%macro remove_account_from_linked_list
    PUSH %%after
    SWAP1
    %jump(remove_account)
%%after:
%endmacro

/// Remove the address and its value from the access list.
/// Panics if the key is not in the list.
global remove_account:
    // stack: addr, retdest
    PROVER_INPUT(linked_list::remove_account)
    // stack: pred_ptr/4, addr, retdest
    %get_valid_account_ptr
    // stack: pred_ptr, addr, retdest
    %add_const(3)
    // stack: next_ptr_ptr, addr, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr, addr, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_addr, next_ptr, next_ptr_ptr, addr, retdest
    DUP4
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr, retdest
    %add_const(3)
    // stack: next_next_ptr_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, addr, retdest
    SWAP1
    PUSH @U256_MAX
    MSTORE_GENERAL
    // stack: next_next_ptr, next_ptr_ptr, addr, retdest
    MSTORE_GENERAL
    POP
    JUMP


//
//
// STORAGE linked list
//
//

%macro store_initial_slots
    PUSH %%after
    %jump(store_initial_slots)
%%after:
%endmacro


/// Iterates over the inital account linked list and shallow copies
/// the accounts, storing a pointer to the copied account in the node.
global store_initial_slots:
    // stack: retdest

    PUSH  @SEGMENT_STORAGE_LINKED_LIST
    %next_slot

global debug_el_loooooop:
loop_store_initial_slots:
    // stack: current_node_ptr
    %get_trie_data_size
    DUP2
    MLOAD_GENERAL
    // stack: current_addr, cpy_ptr, current_node_ptr, retdest
    %eq_const(@U256_MAX)
    %jumpi(store_initial_slots_end)
    DUP2
    %add_const(2)
    MLOAD_GENERAL
global debug_payload_ptr:
    // stack: payload_ptr, cpy_ptr, current_node_ptr, retdest
    %mload_trie_data
    %append_to_trie_data
    // stack: cpy_ptr, current_node_ptr, retdest
    DUP2
    %add_const(3)
    SWAP1
global store_cpy_ptr:
    MSTORE_GENERAL // Store cpy_ptr
    %next_slot
    %jump(loop_store_initial_slots)

store_initial_slots_end:
    %pop2
    JUMP


%macro insert_slot
    %stack (addr, key, ptr) -> (addr, key, ptr, %%after)
    %jump(insert_slot)
%%after:
    // stack: cold_access, value_ptr
%endmacro

%macro insert_slot_no_return
    %insert_slot
    %pop2
%endmacro

// Multiply the value at the top of the stack, denoted by ptr/5, by 5
// and abort if ptr/5 >= (mem[@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN] - @SEGMENT_STORAGE_LINKED_LIST)/5
// In this way @SEGMENT_STORAGE_LINKED_LIST + 5*ptr/5 must be pointing to the beginning of a node.
// TODO: Maybe we should check here if the node have been deleted.
%macro get_valid_slot_ptr
     // stack: ptr/5
    DUP1
    %mload_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    %sub_const(@SEGMENT_STORAGE_LINKED_LIST)
    // By construction, the unscaled list len
    // must be multiple of 5
    %div_const(5)
    // stack: accessed_strg_keys_len/5, ptr/5, ptr/5
    %assert_gt
    %mul_const(5)
    %add_const(@SEGMENT_STORAGE_LINKED_LIST)
%endmacro

/// Inserts the pair (addres, storage_key) and a new payload pointer into the linked list if it is not already present,
/// or modify its payload if it was already present.
/// Return `1, new_payload_ptr` if the storage key was inserted, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
global insert_slot_with_value:
    // stack: addr, key, value, retdest
    PROVER_INPUT(linked_list::insert_slot)
    // stack: pred_ptr/5, addr, key, value, retdest
    %get_valid_slot_ptr

    // stack: pred_ptr, addr, key, value, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, key, value, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_slot_with_value)
    // stack: pred_addr, pred_ptr, addr, key, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, key, value, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: pred_key, pred_ptr, addr, key, value, retdest
    DUP1 DUP5
    GT
    %jumpi(insert_new_slot_with_value)
    // stack: pred_key, pred_ptr, addr, key, value, retdest
    DUP4
    // We know that key <= pred_key. It must hold that pred_key == key.
    %assert_eq
    
    // stack: pred_ptr, addr, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(4)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, slot_found_write_value)
    // The storage key is not in the list.
    PANIC

insert_new_slot_with_value:
    // stack: pred_addr or pred_key, pred_ptr, addr, key, value, retdest
    POP
    // get the value of the next address
    %add_const(4)
    // stack: next_ptr_ptr, addr, key, value, retdest
    %mload_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_addr, next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    DUP1
    DUP6
    // Here, (addr > pred_addr) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (addr < next_addr), meaning the new value can be inserted between pred_ptr and next_ptr.
    LT
    %jumpi(next_node_ok_with_value)
    // If addr <= next_addr, then it addr must be equal to next_addr
    // stack: next_addr, next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    DUP5
    %assert_eq
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    DUP1 // This is added just to have the correct stack in next_node_ok
    DUP7
    // The next key must be strictly larger
    %assert_lt
next_node_ok_with_value:
    // stack: next_addr or next_key, next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    POP
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, value, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, addr, key, value, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, key, value, retdest
    // Write the address in the new node
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, key, value, retdest
    // Write the key in the new node
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, addr, key, value, retdest
    // Append the value to `TrieDataSegment` and write the resulting payload_ptr.
    %increment
    DUP1
    %get_trie_data_size
    // stack: new_payload_ptr, new_ptr+2, new_ptr+2, next_ptr, addr, key, value, retdest
    %stack (new_payload_ptr, new_payload_ptr_ptr, new_payload_ptr_ptr, next_ptr, addr, key, value) -> (value, new_payload_ptr, new_payload_ptr_ptr, new_payload_ptr_ptr, next_ptr, addr, key, new_payload_ptr)
    %append_to_trie_data
    MSTORE_GENERAL

    // stack: new_ptr + 2, next_ptr, addr, key, new_payload_ptr, retdest
    // Store the payload ptr copy
    %increment
    DUP1
    DUP6
    %clone_slot
    MSTORE_GENERAL
    // stack: new_ptr + 3, next_ptr, addr, key, new_payload_ptr, retdest
    %increment
    DUP1
    // stack: new_next_ptr, new_next_ptr, next_ptr, addr, key, new_payload_ptr, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr, addr, key, new_payload_ptr, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    // stack: addr, key, new_payload_ptr, retdest
    %pop2
    PUSH 0
    SWAP1
    SWAP2
    JUMP

slot_found_write_value:
    // stack: pred_ptr, addr, key, value, retdest
    %add_const(2) MLOAD_GENERAL
    %stack (payload_ptr, addr, key, value) -> (payload_ptr, value, payload_ptr)
    %mstore_trie_data
    // stack: payload_ptr, retdest
    // the cold_access is no longer used here, so we can set any value.
    %stack (payload_ptr, retdest) -> (retdest, 0, payload_ptr)
    JUMP

%macro insert_slot_with_value
    %stack (addr, slot, value) -> (addr, slot, value, %%after)
    SWAP1 %slot_to_storage_key
    SWAP1 %addr_to_state_key
    %jump(insert_slot_with_value)
%%after:
    // stack: cold_access, value_ptr
%endmacro

/// Inserts the pair (addres, storage_key) and payload pointer into the linked list if it is not already present,
/// or modify its payload if it was already present.
/// Return `1, payload_ptr` if the storage key was inserted, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
global insert_slot:
    // stack: addr, key, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_slot)
    // stack: pred_ptr/5, addr, key, payload_ptr, retdest
    %get_valid_slot_ptr

    // stack: pred_ptr, addr, key, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, key, payload_ptr, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // we need to insert a new node.
    %jumpi(insert_new_slot)
    // stack: pred_addr, pred_ptr, addr, key, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: pred_key, pred_ptr, addr, key, payload_ptr, retdest
    DUP1 DUP5
    GT
global before_jumpi:
    %jumpi(insert_new_slot)
    // stack: pred_key, pred_ptr, addr, key, payload_ptr, retdest
    DUP4
    // We know that key <= pred_key. It must hold that pred_key == key.
    %assert_eq
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(4)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, slot_found_write)
    // The storage key is not in the list.
    PANIC

slot_found_write:
    // The slot was already in the list
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    // Load the the payload pointer and access counter
    %add_const(2)
    DUP1
    MLOAD_GENERAL
    // stack: orig_payload_ptr, pred_ptr + 2, addr, key, payload_ptr, retdest
    SWAP1
    DUP5
global debug_store_new_payload:
    MSTORE_GENERAL // Store the new payload
    // TODO: remove the unused cold access
    %stack (orig_payload_ptr, addr, key, payload_ptr, retdest) -> (retdest, 0, orig_payload_ptr)
    JUMP
insert_new_slot:
    // stack: pred_addr or pred_key, pred_ptr, addr, key, payload_ptr, retdest
    POP
    // get the value of the next address
    %add_const(4)
    // stack: next_ptr_ptr, addr, key, payload_ptr, retdest
    %mload_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    DUP2
    MLOAD_GENERAL
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %eq_const(@U256_MAX)
    %assert_zero
    DUP1
    MLOAD_GENERAL
    // stack: next_addr, next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    DUP1
    DUP6
    // Here, (addr > pred_addr) || (pred_ptr == @SEGMENT_ACCOUNTS_LINKED_LIST).
    // We should have (addr < next_addr), meaning the new value can be inserted between pred_ptr and next_ptr.
    LT
    %jumpi(next_node_ok)
    // If addr <= next_addr, then it addr must be equal to next_addr
    // stack: next_addr, next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    DUP5
    %assert_eq
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    DUP1 // This is added just to have the correct stack in next_node_ok
    DUP7
    // The next key must be strictly larger
    %assert_lt
next_node_ok:
    // stack: next_addr or next_key, next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    POP
    // stack: next_ptr, new_ptr, next_ptr_ptr, addr, key, payload_ptr, retdest
    SWAP2
    DUP2
    // stack: new_ptr, next_ptr_ptr, new_ptr, next_ptr, addr, key, payload_ptr, retdest
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, key, payload_ptr, retdest
    // Write the address in the new node
    DUP1
    DUP4
    MSTORE_GENERAL
    // stack: new_ptr, next_ptr, addr, key, payload_ptr, retdest
    // Write the key in the new node
    %increment
    DUP1
    DUP5
    MSTORE_GENERAL
    // stack: new_ptr + 1, next_ptr, addr, key, payload_ptr, retdest
    // Store payload_ptr
    %increment
    DUP1
    DUP6
    MSTORE_GENERAL

    // stack: new_ptr + 2, next_ptr, addr, key, payload_ptr, retdest
    // Store the copy of payload_ptr
    %increment
    DUP1
    DUP6
    MSTORE_GENERAL
    // stack: new_ptr + 3, next_ptr, addr, key, payload_ptr, retdest
    %increment
    DUP1
    // stack: new_next_ptr, new_next_ptr, next_ptr, addr, key, payload_ptr, retdest
    SWAP2
    MSTORE_GENERAL
    // stack: new_next_ptr, addr, key, payload_ptr, retdest
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    // stack: addr, key, payload_ptr, retdest
    // TODO: Don't for get to %journal_add_storage_loaded!!!
    %pop2
    PUSH 0
    SWAP1
    SWAP2
    JUMP

/// Search the pair (address, storage_key) in the storage the linked list.
/// Returns `1, payload_ptr` if the storage key was inserted, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
// TODO: Not sure if this is correct, bc if a value is not found we need to return 0 but keep track of it for
// having the right cold_access
global search_slot:
    // stack: addr, key, payload_ptr, retdest
    PROVER_INPUT(linked_list::insert_slot)
    // stack: pred_ptr/5, addr, key, payload_ptr, retdest
    %get_valid_slot_ptr

    // stack: pred_ptr, addr, key, payload_ptr, retdest
    DUP1
    MLOAD_GENERAL
    DUP1
    // stack: pred_addr, pred_addr, pred_ptr, addr, key, payload_ptr, retdest
    DUP4 
    GT
    DUP3 %eq_const(@SEGMENT_STORAGE_LINKED_LIST)
    ADD // OR
    // If the predesessor is strictly smaller or the predecessor is the special
    // node with key @U256_MAX (and hence we're inserting a new minimum), then
    // the slot was not found
    %jumpi(slot_not_found)
    // stack: pred_addr, pred_ptr, addr, key, payload_ptr, retdest
    // If we are here we know that addr <= pred_addr. But this is only possible if pred_addr == addr.
    DUP3
    %assert_eq
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: pred_key, pred_ptr, addr, key, payload_ptr, retdest
    DUP1 DUP5
    GT
    %jumpi(slot_not_found)
    // stack: pred_key, pred_ptr, addr, key, payload_ptr, retdest
    DUP4
    // We know that key <= pred_key. It must hold that pred_key == key.
    %assert_eq
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    // Check that this is not a deleted node
    DUP1
    %add_const(4)
    MLOAD_GENERAL
    %jump_neq_const(@U256_MAX, slot_found_no_write)
    // The storage key is not in the list.
    PANIC

global debug_slot_not_found:
slot_not_found:    
    // stack: pred_addr_or_pred_key, pred_ptr, addr, key, payload_ptr, retdest
    %stack (pred_addr_or_pred_key, pred_ptr, addr, key, payload_ptr, retdest)
        -> (retdest, 1, payload_ptr)
    JUMP

slot_found_no_write:
    // The slot was already in the list
    // stack: pred_ptr, addr, key, payload_ptr, retdest
    // Load the the payload pointer and access counter
    %add_const(2)
    MLOAD_GENERAL
    // stack: orig_payload_ptr, addr, key, payload_ptr, retdest
    // TODO: remove the now unused cold access (the 0)
    %stack (orig_payload_ptr, addr, key, payload_ptr, retdest) -> (retdest, 0, orig_payload_ptr)
    JUMP


%macro remove_slot
    %stack (addr, key) -> (addr, key, %%after)
    %jump(remove_slot)
%%after:
%endmacro

/// Remove the storage key and its value from the list.
/// Panics if the key is not in the list.
global remove_slot:
    // stack: addr, key, retdest
    PROVER_INPUT(linked_list::remove_slot)
    // stack: pred_ptr/5, addr, key, retdest
    %get_valid_slot_ptr
    // stack: pred_ptr, addr, key, retdest
    %add_const(4)
    // stack: next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_addr, next_ptr, next_ptr_ptr, addr, key, retdest
    DUP4
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, next_ptr_ptr, addr, key, retdest
    DUP5
    %assert_eq
    // stack: next_ptr, next_ptr_ptr, addr, key, retdest
    %add_const(4)
    // stack: next_next_ptr_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, addr, key, retdest
    // Mark the next node as deleted
    SWAP1
    PUSH @U256_MAX
    MSTORE_GENERAL
    // stack: next_next_ptr, next_ptr_ptr, addr, key, retdest
    MSTORE_GENERAL
    %pop2
    JUMP

/// Called when an account is deleted: it deletes all slots associated with the account.
global remove_all_account_slots:
    // stack: addr, retdest
    PROVER_INPUT(linked_list::remove_address_slots)
    // pred_ptr/5, retdest
    %get_valid_slot_ptr

global debug_after_valid_ptr:
    // stack: pred_ptr, addr, retdest
    // First, check that the previous address is not `addr`
    DUP1 MLOAD_GENERAL
    // stack: pred_addr, pred_ptr, addr, retdest
    DUP3 EQ %jumpi(panic)
    // stack: pred_ptr, addr, retdest
    // Now, while the next address is `addr`, remove the slot.

remove_all_slots_loop:
    // stack: pred_ptr, addr, retdest
    %add_const(4) MLOAD_GENERAL DUP1
    // stack: cur_ptr, cur_ptr, addr, retdest
    DUP1 %eq_const(@U256_MAX) %jumpi(remove_all_slots_end)
    MLOAD_GENERAL
    // stack: cur_addr, cur_ptr, addr, retdest
    DUP1 DUP4 EQ ISZERO %jumpi(remove_all_slots_end)
    // stack: cur_addr, cur_ptr, addr, retdest
    DUP2 %increment MLOAD_GENERAL SWAP1
    // stack: cur_addr, cur_key, cur_ptr, addr, retdest
    %remove_slot
    // stack: cur_ptr, addr, retdest
    %jump(remove_all_slots_loop)

remove_all_slots_end:
    // stack: cur_addr, cur_ptr, addr, retdest
    %pop3 JUMP

%macro remove_all_account_slots
    %stack (addr) -> (addr, %%after)
    %jump(remove_all_account_slots)
%%after:
%endmacro

%macro read_accounts_linked_list
    %stack (addr) -> (addr, 0, %%after)
    %addr_to_state_key
    %jump(search_account)
%%after:
    // stack: cold_access, account_ptr
    POP
%endmacro

%macro read_storage_linked_list
    // stack: slot
    %slot_to_storage_key
    %address
    %addr_to_state_key
    %stack (addr, key) -> (addr, key, 0, %%after)
    %jump(search_slot)
%%after:
    // stack: cold_access, slot_ptr
    POP
%endmacro

%macro read_storage_linked_list_w_addr
    // stack: slot, address
    %slot_to_storage_key
    SWAP1
    %addr_to_state_key
    %stack (addr, key) -> (addr, key, 0, %%after)
    %jump(search_slot)
%%after:
    // stack: cold_access, slot_ptr
    POP
%endmacro

%macro first_account
    // stack: empty
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %next_account
%endmacro

%macro next_account
    // stack: node_ptr
    %add_const(3)
    MLOAD_GENERAL
    // stack: next_node_ptr
%endmacro

%macro first_slot
    // stack: empty
    PUSH @SEGMENT_STORAGE_LINKED_LIST
    %next_slot
%endmacro

%macro next_slot
    // stack: node_ptr
    %add_const(4)
    MLOAD_GENERAL
    // stack: next_node_ptr
%endmacro

%macro read_slot_linked_list
    // stack: address, slot
    %addr_to_state_key
    SWAP1 %slot_to_storage_key
    %stack (slot_key, addr_key) -> (addr_key, slot_key, 0, %%after)
    %jump(search_slot)
%%after:
%endmacro
