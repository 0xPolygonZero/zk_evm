/// EIP-4788: Beacon block root in the EVM
/// <https://eips.ethereum.org/EIPS/eip-4788#pseudocode>
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

/// Pre-stack: (empty)
/// Post-stack: (empty)
global set_beacon_root:
    // stack: (empty)
    PUSH txn_loop
    %timestamp
    // stack: timestamp, retdest
    PUSH @HISTORY_BUFFER_LENGTH
    DUP2
    // stack: timestamp, 8191, timestamp, retdest
    MOD
    // stack: timestamp_idx, timestamp, retdest
    %slot_to_storage_key
    // stack: timestamp_slot_key, timestamp, retdest
    PUSH @BEACON_ROOTS_CONTRACT_STATE_KEY
    %parent_beacon_block_root
    // stack: calldata, state_key, timestamp_slot_key, timestamp, retdest
    PUSH @HISTORY_BUFFER_LENGTH
    DUP5
    MOD
    // stack: timestamp_idx, calldata, state_key, timestamp_slot_key, timestamp, retdest
    %add_const(@HISTORY_BUFFER_LENGTH)
    // stack: root_idx, calldata, state_key, timestamp_slot_key, timestamp, retdest
    %slot_to_storage_key
    // stack: root_slot_key, calldata, state_key, timestamp_slot_key, timestamp, retdest
    DUP3
    // stack: state_key, root_slot_key, calldata, state_key, timestamp_slot_key, timestamp, retdest
    DUP3 ISZERO %jumpi(delete_root_idx_slot)
    // stack: state_key, root_slot_key, calldata, state_key, timestamp_slot_key, timestamp, 
global debug_inserting_first_slot:
    %insert_slot_from_addr_key
    // stack: state_key, timestamp_idx, timestamp, retdest
global debug_inserting_second_slot:
    %insert_slot_from_addr_key
    // stack: retdest
    JUMP

delete_root_idx_slot:
    // stack: state_key, root_slot_idx, 0, state_key, timestamp_idx, timestamp, retdest
    DUP2 DUP2
    %search_slot_from_addr_key
    // stack: slot_exists, state_key, root_slot_idx, 0, state_key, timestamp_idx, timestamp, retdest
    %jumpi(remove_root_idx_slot)
    // stack: state_key, root_slot_key, 0, state_key, timestamp_idx, timestamp, retdest
    %pop3
    // stack: state_key, timestamp_idx, timestamp, retdest
    %insert_slot_from_addr_key
    // stack: retdest
    JUMP

remove_root_idx_slot:
    // stack: state_key, root_slot_idx, 0, state_key, timestamp_slot_idx, timestamp, retdest
    %remove_slot_from_addr_key
    POP
    // stack: state_key, timestamp_slot_idx, timestamp, retdest
    %insert_slot_from_addr_key
    // stack: retdest
    JUMP
