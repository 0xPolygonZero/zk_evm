/// EIP-4788: Beacon block root in the EVM
/// <https://eips.ethereum.org/EIPS/eip-4788#pseudocode>
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

global set_beacon_root:
    PUSH set_global_exit_roots
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
    %addr_to_state_key
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
    // stack: state_key, root_slot_key, calldata, state_key, timestamp_slot_key, timestamp, retdest
    %insert_slot_with_value_from_keys
    // stack: state_key, timestamp_slot_key, timestamp, retdest
    %insert_slot_with_value_from_keys
    // stack: retdest
    JUMP

delete_root_idx_slot:
    // stack: state_key, root_slot_key, 0, state_key, timestamp_slot_key, timestamp, retdest
    DUP3 DUP3 DUP3
    %search_slot
    // stack: slot_exists, state_key, root_slot_key, 0, state_key, timestamp_slot_key, timestamp, retdest
    %jumpi(remove_root_idx_slot)
    // stack: state_key, root_slot_key, 0, state_key, timestamp_slot_key, timestamp, retdest
    %pop3
    // stack: state_key, timestamp_slot_key, timestamp, retdest
    %insert_slot_with_value_from_keys
    // stack: retdest
    JUMP

remove_root_idx_slot:
    // stack: state_key, root_slot_key, 0, state_key, timestamp_slot_key, timestamp, retdest
    %stack(state_key, storage_key, zero) -> (storage_key, state_key)
    %remove_slot
    // stack: state_key, timestamp_slot_key, timestamp, retdest
    %insert_slot_with_value_from_keys
    // stack: retdest
    JUMP
