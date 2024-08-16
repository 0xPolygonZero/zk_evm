/// At the top of the block, the global exit roots (if any) are written to storage.
/// Global exit roots (GER) are of the form `(timestamp, root)` and are loaded from prover inputs.
/// The timestamp is written to the storage of address `GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY` in the slot `keccak256(abi.encodePacked(root, GLOBAL_EXIT_ROOT_STORAGE_POS))`.
/// See https://github.com/0xPolygonHermez/cdk-erigon/blob/zkevm/zk/utils/global_exit_root.go for reference.
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

global set_global_exit_roots:
    // stack: (empty)
    PUSH txn_loop
    // stack: retdest
    PUSH @GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY
    %addr_to_state_key
    PROVER_INPUT(ger)
    // stack: num_ger, state_key, retdest
    PUSH 0
ger_loop:
    // stack: i, num_ger, state_key, retdest
    DUP2 DUP2 EQ %jumpi(ger_loop_end)
    PROVER_INPUT(ger)
    // stack: timestamp, i, num_ger, state_key, retdest
    PUSH @GLOBAL_EXIT_ROOT_STORAGE_POS
    PROVER_INPUT(ger)
    // stack: root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, state_key, retdest
    PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, state_key, retdest
    MSTORE_32BYTES_32
    // stack: addr, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, state_key, retdest
    MSTORE_32BYTES_32
    // stack: addr, timestamp, i, num_ger, state_key, retdest
    POP
    // stack: timestamp, i, num_ger, state_key, retdest
    PUSH 64 PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, len, timestamp, i, num_ger, state_key, retdest
    KECCAK_GENERAL
    // stack: slot, timestamp, i, num_ger, state_key, retdest
    %slot_to_storage_key
    // stack: slot_key, timestamp, i, num_ger, state_key, retdest
    DUP5
    // stack: state_key, slot_key, timestamp, i, num_ger, state_key, retdest
    %insert_slot_with_value_from_keys
    // stack: i, num_ger, state_key, retdest
    %increment
    %jump(ger_loop)

ger_loop_end:
    // stack: i, num_ger, state_key, retdest
    %pop3 JUMP
