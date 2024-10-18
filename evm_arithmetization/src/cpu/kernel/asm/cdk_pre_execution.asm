/// CDK-Erigon pre-block execution logic.
/// Reference implementation: `cdk-erigon/core/state/intra_block_state_zkevm.go`.
/// This currently supports the Etrog upgrade.

/// Pre-stack: (empty)
/// Post-stack: (empty)
global pre_block_execution:
    // stack: (empty)
    PUSH txn_loop
    // stack: retdest
    PUSH @ADDRESS_SCALABLE_L2
    %is_non_existent
    %jumpi(create_scalable_l2_account)

global update_scalable_block_number:
    // stack: retdest
    %blocknumber
global debug_blocknumber:
    PUSH @LAST_BLOCK_STORAGE_POS
    // stack: last_block_slot, block_number, retdest
    %write_scalable_storage
    // stack: retdest
global debug_wtf_is_happening_with_retdest:
    // Check timestamp
    PUSH @TIMESTAMP_STORAGE_POS
    PUSH @ADDRESS_SCALABLE_L2
    %read_slot_from_addr_key
    // stack: old_timestamp, retdest
    %timestamp
global debug_el_timestamp:
    GT 
global debug_before_jumpi:
    %jumpi(update_scalable_timestamp)

global update_scalable_prev_block_root_hash:
    // stack: retdest
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE)
    // stack: prev_block_root, retdest
    PUSH @STATE_ROOT_STORAGE_POS
    PUSH 1 %blocknumber SUB
    // stack: block_number - 1, STATE_ROOT_STORAGE_POS, prev_block_root, retdest
    PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, block_number - 1, STATE_ROOT_STORAGE_POS, prev_block_root, retdest
    MSTORE_32BYTES_32
    // stack: addr, STATE_ROOT_STORAGE_POS, prev_block_root, retdest
    MSTORE_32BYTES_32
    // stack: addr, prev_block_root, retdest
    POP
    // stack: prev_block_root, retdest
    PUSH 64 PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, len, prev_block_root, retdest
    KECCAK_GENERAL
    // stack: slot, prev_block_root, retdest
    %write_scalable_storage
    // stack: retdest

// Note: We assume that if the l1 info tree has been re-used or the GER does not exist,
// the payload will not contain any root to store, in which case calling `PROVER_INPUT(ger)`
// will return `U256::MAX` causing this to return early.
global update_scalable_l1blockhash:
    // stack: retdest
    PROVER_INPUT(ger)
    // stack: l1blockhash?, retdest
    DUP1 %eq_const(@U256_MAX) %jumpi(skip_and_exit)
    PUSH @SEGMENT_KERNEL_GENERAL
    // stack: addr, l1blockhash, retdest
    PUSH @GLOBAL_EXIT_ROOT_STORAGE_POS
    PROVER_INPUT(ger)
    // stack: root, GLOBAL_EXIT_ROOT_STORAGE_POS, addr, l1blockhash, retdest
    DUP3
    // stack: addr, root, GLOBAL_EXIT_ROOT_STORAGE_POS, addr, l1blockhash, retdest
    MSTORE_32BYTES_32
    // stack: addr', GLOBAL_EXIT_ROOT_STORAGE_POS, addr, l1blockhash, retdest
    MSTORE_32BYTES_32
    // stack: addr'', addr, l1blockhash, retdest
    %stack (addr_2, addr) -> (addr, 64)
    // stack: addr, len, l1blockhash, retdest
    KECCAK_GENERAL
    // stack: slot, l1blockhash, retdest
    PUSH @GLOBAL_EXIT_ROOT_MANAGER_L2_STATE_KEY
    // stack: state_key, slot, l1blockhash, retdest
    %insert_slot_from_addr_key
    // stack: retdest
    JUMP

skip_and_exit:
    // stack: null, retdest
    POP
    JUMP

global update_scalable_timestamp:
    // stack: retdest
    %timestamp
global debug_le_timestamp:
    PUSH @TIMESTAMP_STORAGE_POS
    // stack: timestamp_slot, timestamp, retdest
    %write_scalable_storage
    %jump(update_scalable_prev_block_root_hash)

global create_scalable_l2_account:
    // stack: (empty)
    PUSH update_scalable_block_number
    // stack: retdest
    // Since nonce, balance and code length are 0 we only need to set
    // the code hash 
    
    // stack: retdest
    PUSH @EMPTY_STRING_HASH
    PUSH @ADDRESS_SCALABLE_L2
global debug_setting_scalable_code:
    %set_code // code hash

    // stack: retdest
    JUMP

%macro write_scalable_storage
    // stack: slot, value
    PUSH @ADDRESS_SCALABLE_L2
    // stack: state_key, slot, value
    %insert_slot_from_addr_key
    // stack: (empty)
%endmacro
