/// Access lists for addresses and storage keys.
/// The access list is stored in a sorted linked list in SEGMENT_ACCESSED_ADDRESSES for addresses and
/// SEGMENT_ACCESSED_STORAGE_KEYS segment for storage keys. The length of
/// the segments is stored in the global metadata.
/// Both arrays are stored in the kernel memory (context=0).
/// Searching and inserting is done by guessing the predecessor in the list.
/// If the address/storage key isn't found in the array, it is inserted at the end.

// Initialize an empty linked list (@U256_MAX)⮌
// which is written as [@U256_MAX, _, _, @SEGMENT_ACCOUNTS_LINKED_LIST] in SEGMENT_ACCOUNTS_LINKED_LIST
// The stire values at the respective positions are:
// - 0: The account key
// - 1: A ptr to the payload (the account values)
// - 2: A counter indicating if the number of times this address have been accessed.
// - 3: A ptr (in segment @SEGMENT_ACCOUNTS_LINKED_LIST) to the next node in the list.
global init_accounts_linked_list:
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
    JUMP

%macro init_accounts_linked_list
    PUSH %%after
    %jump(init_account_linked_list)
%%after:
%endmacro

%macro insert_account
    %stack (addr, ptr) -> (addr, ptr, %%after)
    %jump(insert_account)
%%after:
    // stack: cold_access
%endmacro

%macro insert_account_no_return
    %insert_account
    POP
%endmacro

// Multiply the ptr at the top of the stack by 4
// and abort if 4*ptr - SEGMENT_ACCOUNTS_LINKED_LIST >= @GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN
// In this way ptr must be poiting to the begining of a node.
%macro get_valid_account_ptr
    // stack: ptr
    %mul_const(4)
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    DUP2
    SUB
    %assert_lt_const(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)
    // stack: 2*ptr
%endmacro

/// Inserts the account addr and payload otr into the linked list if it is not already present.
/// `value` should be the current storage value at the slot `(addr, key)`.
/// Return `0, payload_ptr` if the storage key was inserted, `1, original_ptr` if it was already present
/// and this is the first access, or `0, original_ptr` if it was already present and accessed.
global insert_account:
    // stack: addr, payload_ptr, retdest
    PROVER_INPUT(linked_lists::insert_account)
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
account_found:
    // The address was already in the list
    // stack: pred_ptr, addr, payload_ptr, retdest
    // Load the access counter
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: orig_payload_ptr, pred_ptr, addr, payload_ptr, retdest
    SWAP1
    %add_const(2)
    DUP1
    MLOAD_GENERAL
    %increment
    // stack: access_ctr, access_ctr_ptr, orig_payload_ptr, addr, payload_ptr, retdest
    SWAP1
    DUP2
    // stack: access_ctr, access_ctr_ptr, access_ctr, orig_payload_ptr, addr, payload_ptr, retdest
    MSTORE_GENERAL
    // stack: access_ctr, orig_payload_ptr, addr, payload_ptr, retdest
    // If access_ctr == 1 then this it's a cold access 
    %eq_const(0)
    %stack (cold_access, orig_payload_ptr, addr, payload_ptr) -> (retdest, cold_access, orig_payload_ptr)
    JUMP


/// Remove the storage key and its value from the access list.
/// Panics if the key is not in the list.
global remove_account:
    // stack: addr, key, retdest
    PROVER_INPUT(access_lists::remove_account)
    // stack: pred_ptr/4, addr, key, retdest
    %get_valid_storage_ptr
    // stack: pred_ptr, addr, key, retdest
    %add_const(3)
    // stack: next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: next_key, next_ptr, next_ptr_ptr, addr, key, retdest
    DUP5
    EQ
    DUP2
    MLOAD_GENERAL
    // stack: next_addr, next_key == key, next_ptr, next_ptr_ptr, addr, key, retdest
    DUP5
    EQ
    MUL // AND
    // stack: next_addr == addr AND next_key == key, next_ptr, next_ptr_ptr, addr, key, retdest
    %assert_nonzero
    // stack: next_ptr, next_ptr_ptr, addr, key, retdest
    %add_const(3)
    // stack: next_next_ptr_ptr, next_ptr_ptr, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: next_next_ptr, next_next_ptr_ptr, next_ptr_ptr, addr, key, retdest
    SWAP1
    PUSH @U256_MAX
    MSTORE_GENERAL
    // stack: next_next_ptr, next_ptr_ptr, addr, key, retdest
    MSTORE_GENERAL
    %pop2
    JUMP