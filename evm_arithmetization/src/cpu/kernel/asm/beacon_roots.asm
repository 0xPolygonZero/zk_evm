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
    PUSH @BEACON_ROOTS_CONTRACT_STATE_KEY
    // stack: addr, timestamp_idx, timestamp, retdest

    PUSH write_beacon_roots_to_storage
    %parent_beacon_block_root
    // stack: calldata, write_beacon_roots_to_storage, addr, timestamp_idx, timestamp, retdest
    DUP4
    %add_const(@HISTORY_BUFFER_LENGTH)
    // stack: root_idx, calldata, write_beacon_roots_to_storage, addr, timestamp_idx, timestamp, retdest
    DUP4
    // stack: addr, root_idx, calldata, write_beacon_roots_to_storage, addr, timestamp_idx, timestamp, retdest

    // If the calldata is zero, delete the slot from the storage trie.
    DUP3 ISZERO %jumpi(delete_root_idx_slot)

write_beacon_roots_to_storage:
    // stack: addr, slot, value, retdest
    %key_storage
    // stack: storage_key, value, retdest
    %smt_insert_state
    JUMP

delete_root_idx_slot:
    // stack: addr, root_idx, 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %key_storage
    // stack: key, 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    DUP1 %smt_read_state %mload_trie_data %jumpi(delete)
    // stack: key, 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %pop2 JUMP
delete:
    // stack: key, 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    %smt_delete_state
    // stack: 0, write_beacon_roots_to_storage, timestamp_idx, timestamp, retdest
    POP JUMP