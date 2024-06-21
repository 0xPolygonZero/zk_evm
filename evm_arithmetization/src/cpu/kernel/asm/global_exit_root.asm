/// At the top of the block, the global exit roots (if any) are written to storage.
/// Global exit roots (GER) are of the form `(timestamp, root)` and are loaded from prover inputs.
/// The timestamp is written to the storage of address `GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY` in the slot `keccak256(abi.encodePacked(root, GLOBAL_EXIT_ROOT_STORAGE_POS))`.
/// See https://github.com/0xPolygonHermez/cdk-erigon/blob/zkevm/zk/utils/global_exit_root.go for reference.
///
/// *NOTE*: This will panic if one of the provided timestamps is zero.

global set_global_exit_roots:
    // stack: (empty)
    PUSH start_txn
    // stack: retdest
    PUSH @GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY
    // stack: addr, retdest
    PROVER_INPUT(ger)
    // stack: num_ger, addr, retdest
    PUSH 0
ger_loop:
    // stack: i, num_ger, addr, 
    DUP2 DUP2 EQ %jumpi(ger_loop_end)
    PROVER_INPUT(ger)
    // stack: timestamp, i, num_ger, addr, retdest
    PUSH @GLOBAL_EXIT_ROOT_STORAGE_POS
    PROVER_INPUT(ger)
    // stack: root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, addr, retdest
    PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, root, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, addr, retdest
    MSTORE_32BYTES_32
    // stack: addr, GLOBAL_EXIT_ROOT_STORAGE_POS, timestamp, i, num_ger, addr, retdest
    MSTORE_32BYTES_32
    // stack: addr, timestamp, i, num_ger, addr, retdest
    POP
    // stack: timestamp, i, num_ger, addr, retdest
    PUSH 64 PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, len, timestamp, i, num_ger, addr, retdest
    KECCAK_GENERAL
    // stack: slot, timestamp, i, num_ger, addr, retdest

write_timestamp_to_storage:
    // stack: slot, timestamp, i, num_ger, addr, retdest
    DUP5
    // stack: addr, slot, timestamp, i, num_ger, addr, retdest
    %key_storage
    // stack: storage_key, timestamp, i, num_ger, addr, retdest
    // If the current value is non-zero, do nothing.
    DUP1 %smt_read_state %mload_trie_data %jumpi(do_nothing)

    // stack: storage_key, timestamp, i, num_ger, addr, retdest
    %smt_insert_state
    // stack: i, num_ger, addr, retdest
    %increment
    %jump(ger_loop)

ger_loop_end:
    // stack: i, num_ger, addr, retdest
    %pop3 JUMP

do_nothing:
    // stack: storage_key, timestamp, i, num_ger, addr, retdest
    %pop2
    // stack: i, num_ger, addr, retdest
    %increment
    %jump(ger_loop)
