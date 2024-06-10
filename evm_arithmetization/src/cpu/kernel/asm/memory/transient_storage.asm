// Transient data storage


/// The transient storage is stored in an array. The length of the array is stored in the global metadata.
/// For storage keys, the address and key are stored as two consecutive elements.
/// The array is stored in the SEGMENT_TRANSIENT_STORAGE segment in the kernel memory (context=0).
/// Searching and inserting is done by doing a linear search through the array.
/// If the key isn't found in the array, it is inserted at the end.
/// TODO: Look into using a more efficient data structure.

/// The initial length, 0, must be scaled by its segment for
/// comparison with the accumulator when iterating through the list.
%macro init_transient_storage_len
    PUSH @SEGMENT_TRANSIENT_STORAGE
    %mstore_global_metadata(@GLOBAL_METADATA_TRANSIENT_STORAGE_LEN)
%endmacro

%macro search_transient_storage
    %stack (addr, key) -> (addr, key, %%after)
    %jump(search_transient_storage)
%%after:
    // stack:    (is_present, pos, addr, key, val)
%endmacro

/// Looks for an address, key pair into the transient storage.
/// Returns 1 and the position in @SEGMENT_TRANSIENT_STORAGE if present,
/// or 0 and @GLOBAL_METADATA_TRANSIENT_STORAGE_LEN if not.
global search_transient_storage:
    // stack: addr, key, retdest
    %mload_global_metadata(@GLOBAL_METADATA_TRANSIENT_STORAGE_LEN)
    // stack: len, addr, key, retdest
    PUSH @SEGMENT_TRANSIENT_STORAGE
    // stack: i = 0, len, addr, key, retdest
search_transient_storage_loop:
    // `i` and `len` are both scaled by SEGMENT_TRANSIENT_STORAGE
    %stack (i, len, addr, key, retdest) -> (i, len, i, len, addr, key, retdest)
    EQ %jumpi(search_transient_storage_not_found)
    // stack: i, len, addr, key, retdest
    DUP1
    MLOAD_GENERAL
    // stack: loaded_addr, i, len, addr, key, retdest
    DUP4
    // stack: addr, loaded_addr, i, len, addr, key, retdest
    SUB // functions as NEQ
    // stack: addr != loaded_addr, i, len, addr, key, retdest
    %jumpi(increment_and_loop)

    // Addresses match, but we need to check for keys as well
    DUP1
    %increment
    MLOAD_GENERAL
    // stack: loaded_key, i, len, addr, key, retdest
    DUP5
    // stack: key, loaded_key, i, len, addr, key, retdest
    EQ
    %jumpi(search_transient_storage_found)
increment_and_loop:
    // stack: i, len, addr, key, retdest
    %increment
    %jump(search_transient_storage_loop)

search_transient_storage_not_found:
    %stack (i, len, addr, key, retdest) -> (retdest, 0, i, addr, 0, key) // Return 0 to indicate that the address, key was not found.
    JUMP

search_transient_storage_found:
    // stack: i, len, addr, key, retdest
    DUP1 %add_const(2)
    MLOAD_GENERAL
    %stack (val, i, len, addr, key, retdest) -> (retdest, 1, i, addr, val, key) // Return 1 to indicate that the address was already present.
    JUMP

%macro tload_current
    %stack (slot) -> (slot, %%after)
    %jump(tload_current)
%%after:
%endmacro

global tload_current:
    %address
    // stack: addr, slot, retdest
    %search_transient_storage
    // stack: found, pos, addr, val, slot, retdest
    %jumpi(tload_found)
    // The value is not in memory so we return 0
    %stack (pos, addr, val, slot, retdest) -> (retdest, 0)
    JUMP
tload_found:
    // stack: pos, addr, val, slot, retdest
    %stack (pos, addr, val, slot, retdest) -> (retdest, val)
    JUMP

// Read a word from the current account's transient storage list
//
// Pre stack: kexit_info, slot
// Post stack: value
global sys_tload:
    // stack: kexit_info, slot
    %charge_gas_const(@GAS_WARMACCESS)
    // stack: kexit_info, slot
    SWAP1
    // stack: slot, kexit_info
    %tload_current
    SWAP1

    // stack: kexit_info, value
    EXIT_KERNEL

// Write a word to the current account's transient storage.
//
// Pre stack: kexit_info, slot, value
// Post stack: (empty)

global sys_tstore:
    %check_static
    %charge_gas_const(@GAS_WARMACCESS)
    %stack (kexit_info, slot, value) -> (slot, value, kexit_info)
    %address
    %search_transient_storage
    // stack: found, pos, addr, original_value, slot, value, kexit_info
    POP
    // If the address and slot pair was not present pos will be pointing to the end of the array.
    DUP1 DUP3
    // stack: addr, pos, pos, addr, original_value, slot, value, kexit_info
    MSTORE_GENERAL
    %increment DUP1
    DUP5
    // stack: slot, pos', pos', addr, original_value, slot, value, kexit_info
    MSTORE_GENERAL
    %increment DUP1
    DUP6
    // stack: value, pos'', pos'', addr, original_value, slot, value, kexit_info
    MSTORE_GENERAL
    // stack: pos'', addr, original_value, slot, value, kexit_info
    // If pos'' > @GLOBAL_METADATA_TRANSIENT_STORAGE_LEN we need to also store the new @GLOBAL_METADATA_TRANSIENT_STORAGE_LEN
    %mload_global_metadata(@GLOBAL_METADATA_TRANSIENT_STORAGE_LEN)
    DUP2
    GT
    %jumpi(new_transient_storage_len)
    POP
sys_tstore_charge_gas:
    // stack: addr, original_value, slot, value, kexit_info
    // Check if `value` is equal to `current_value`, and if so exit the kernel early.
    %stack 
        (addr, original_value, slot, value, kexit_info) -> 
        (value, original_value, addr, slot, original_value, kexit_info)
    EQ %jumpi(tstore_noop)

add_to_journal:
    // stack: addr, slot, original_value, kexit_info
    %journal_add_transient_storage_change

    // stack: kexit_info
    EXIT_KERNEL

new_transient_storage_len:
    // Store the new (unscaled) length.
    // stack: pos, addr, original_value, slot, value, kexit_info
    %increment
    // stack: pos + 1, addr, original_value, slot, value, kexit_info
    %mstore_global_metadata(@GLOBAL_METADATA_TRANSIENT_STORAGE_LEN)
    // stack: addr, original_value, slot, value, kexit_info
    %jump(sys_tstore_charge_gas)

tstore_noop:
    // stack: current_value, slot, value, kexit_info
    %pop3
    EXIT_KERNEL
