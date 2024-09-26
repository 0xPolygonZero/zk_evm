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
    PUSH @BEACON_ROOTS_CONTRACT_STATE_KEY
    %parent_beacon_block_root
    // stack: calldata, state_key, timestamp_idx, timestamp, retdest
    PUSH @HISTORY_BUFFER_LENGTH
    DUP4
    // stack: timestamp_idx, calldata, state_key, timestamp_idx, timestamp, retdest
    %add_const(@HISTORY_BUFFER_LENGTH)
    // stack: root_idx, calldata, state_key, timestamp_idx, timestamp, retdest
    DUP3
    // stack: state_key, root_slot_idx, calldata, state_key, timestamp_idx, timestamp, retdest
    DUP3 ISZERO %jumpi(delete_root_idx_slot)
    // stack: state_key, root_slot_idx, calldata, state_key, timestamp_idx, timestamp, retdest
    %insert_beacon_slot
    // stack: state_key, timestamp_idx, timestamp, retdest
    %insert_beacon_slot
    // stack: retdest
    JUMP

%macro insert_beacon_slot
    #[cfg(feature = "eth_mainnet")]
    {
        // stack: state_key, slot, calldata 
        SWAP1
        %slot_to_storage_key
        SWAP1
        %insert_slot_with_value_from_keys
    }
    {
        %key_storage
        %beacon_slot_to_key
        
    }
%endmacro

delete_root_idx_slot:
    // stack: state_key, root_slot_idx, 0, state_key, timestamp_idx, timestamp, retdest
    DUP2 DUP2
    %search_slot
    // stack: slot_exists, state_key, root_slot_idx, 0, state_key, timestamp_idx, timestamp, retdest
// -----> Aca voy
    %jumpi(remove_root_idx_slot)
    // stack: state_key, root_slot_key, 0, state_key, timestamp_idx, timestamp, retdest
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
