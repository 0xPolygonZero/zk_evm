global init:
    PUSH @SEGMENT_REGISTERS_STATES
    // stack: addr_registers
    // First, set the registers correctly and verify their values.
    PUSH 2
    %stack_length SUB
    // stack: prev_stack_len, addr_registers
    // First, check the stack length.
    DUP1
    DUP3 %increment_twice 
    // stack: stack_len_addr, prev_stack_len, prev_stack_len, addr_registers
    MLOAD_GENERAL
    %assert_eq

    // Now, we want to check the stack top. For this, we load
    // the value at offset (prev_stack_len - 1) * (stack_len > 0),
    // since we do not constrain the stack top when the stack is empty.
    // stack: prev_stack_len, addr_registers
    DUP1 PUSH 0 LT
    // stack: 0 < prev_stack_len, prev_stack_len, addr_registers
    PUSH 1 DUP3 SUB
    // stack: prev_stack_len - 1, 0 < prev_stack_len, prev_stack_len, addr_registers
    MUL
    PUSH @SEGMENT_STACK
    GET_CONTEXT
    %build_address
    // stack: stack_top_addr, prev_stack_len, addr_registers
    MLOAD_GENERAL

    // stack: stack_top, prev_stack_len, addr_registers
    DUP3 %add_const(3)
    MLOAD_GENERAL
    // stack: pv_stack_top, stack_top, prev_stack_len, addr_registers
    SUB
    // If the stack length was previously 0, we do not need to check the previous stack top.
    MUL
    // stack: (pv_stack_top - stack_top) * prev_stack_len, addr_registers
    %assert_zero

    // Check the context.
    GET_CONTEXT
    // stack: context, addr_registers
    DUP2 %add_const(4)
    MLOAD_GENERAL %shl_const(64)
    // stack: stored_context, context, addr_registers
    %assert_eq

    // Construct `kexit_info`.
    DUP1 MLOAD_GENERAL
    // stack: program_counter, addr_registers
    DUP2 INCR1
    MLOAD_GENERAL
    // stack: is_kernel, program_counter, addr_registers
    %shl_const(32) ADD
    // stack: is_kernel << 32 + program_counter, addr_registers
    SWAP1 %add_const(5) MLOAD_GENERAL
    // stack: gas_used, is_kernel << 32 + program_counter
    %shl_const(192) ADD
    // stack: kexit_info =  gas_used << 192 + is_kernel << 32 + program_counter
    // Now, we set the PC, is_kernel and gas_used to the correct values and continue the execution.
    EXIT_KERNEL

global main:
    // Initialize accessed addresses and storage keys lists
    %init_access_lists

    // Initialize transient storage length
    %init_transient_storage_len

    // Encode constant nodes
    %initialize_rlp_segment

    // Initialize trie data size.
    PROVER_INPUT(trie_ptr::trie_data_size)
    %mstore_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)

global store_initial:
    // Store the initial accounts and slots for hashing later
    %store_initial_accounts
    %store_initial_slots
   
global after_store_initial:
    // Initialize the transaction and receipt trie root pointers.
    PROVER_INPUT(trie_ptr::txn)
    %mstore_global_metadata(@GLOBAL_METADATA_TXN_TRIE_ROOT)
    PROVER_INPUT(trie_ptr::receipt)
    %mstore_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_ROOT)

global hash_initial_tries:
    // We compute the length of the trie data segment in `mpt_hash` so that we
    // can check the value provided by the prover.
    // The trie data segment is already written by the linked lists

    // First, we compute the initial size of the trie data segment.
    PUSH @ACCOUNTS_LINKED_LISTS_NODE_SIZE
    PUSH @SEGMENT_ACCOUNTS_LINKED_LIST
    %mload_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_NEXT_AVAILABLE)
    SUB
    // stack: accounts_ll_full_len, accounts_ll_node_size
    DIV
    %decrement
    // stack: actual_nb_accounts
    // The initial payloads are written twice, and each payload requires 4 elements.
    PUSH 8 MUL
    INCR1
    // stack: init_trie_data_len
    PUSH @INITIAL_RLP_ADDR
    // stack: rlp_start, init_trie_data_len
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_BEFORE)      %assert_eq
    PUSH @INITIAL_RLP_ADDR
    // stack: rlp_start, trie_data_len
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_BEFORE)  %assert_eq
    // stack: trie_data_full_len
    // Check that the trie data length is correct.
    %mload_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)
    %assert_eq

global start_txns:
    // stack: (empty)
    %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_BEFORE)
    // stack: txn_nb
    DUP1 %scalar_to_rlp
    // stack: txn_counter, txn_nb
    DUP1 %num_bytes %mul_const(2)
    SWAP1
    // stack: txn_counter, num_nibbles, txn_nb
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_BEFORE)
    // stack: init_gas_used, txn_counter, num_nibbles, txn_nb

    #[cfg(feature = eth_mainnet)]
    {
        // If txn_idx == 0, update the beacon_root for Ethereum mainnet.
        DUP4
        ISZERO
        %jumpi(set_beacon_root)
    }
    #[cfg(feature = cdk_erigon)]
    {
        // If txn_idx == 0, perform pre-state execution for CDK erigon.
        DUP4
        ISZERO
        %jumpi(pre_block_execution)
    }

    // stack: init_gas_used, txn_counter, num_nibbles, txn_nb
global txn_loop:
    // If the prover has no more txns for us to process, halt.
    PROVER_INPUT(end_of_txns)
    #[cfg(feature = eth_mainnet)]
    {
        %jumpi(execute_withdrawals)
    }
    #[cfg(not(feature = eth_mainnet))]
    {
        %jumpi(perform_final_checks)
    }

    // Call route_txn. When we return, we will process the txn receipt.
    PUSH txn_loop_after

    // stack: retdest, prev_gas_used, txn_counter, num_nibbles, txn_nb
    %stack(retdest, prev_gas_used, txn_counter, num_nibbles) -> (txn_counter, num_nibbles, retdest, prev_gas_used, txn_counter, num_nibbles) 
    %jump(route_txn)

global txn_loop_after:
    // stack: success, leftover_gas, cur_cum_gas, prev_txn_counter, prev_num_nibbles, txn_nb
    DUP5 DUP5 %increment_bounded_rlp
    // stack: txn_counter, num_nibbles, success, leftover_gas, cur_cum_gas, prev_txn_counter, prev_num_nibbles, txn_nb
    %stack (txn_counter, num_nibbles, success, leftover_gas, cur_cum_gas, prev_txn_counter, prev_num_nibbles) -> (success, leftover_gas, cur_cum_gas, prev_txn_counter, prev_num_nibbles, txn_counter, num_nibbles)
    %process_receipt

    // stack: new_cum_gas, txn_counter, num_nibbles, txn_nb
    INCR4

    // Re-initialize memory values before processing the next txn.
    %reinitialize_memory_pre_txn

    // stack: new_cum_gas, txn_counter, num_nibbles, new_txn_number
    %jump(txn_loop)

#[cfg(feature = eth_mainnet)]
{
    global execute_withdrawals:
        // stack: cum_gas, txn_counter, num_nibbles, txn_nb
        %withdrawals
}

global perform_final_checks:
    // stack: cum_gas, txn_counter, num_nibbles, txn_nb
    // Check that we end up with the correct `cum_gas`, `txn_nb` and bloom filter.
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_AFTER) %assert_eq
    DUP3
    %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_AFTER) %assert_eq
    %pop3

    // We set a dummy value as an initial trie data length,
    // since the final transaction and receipt tries have already been
    // added to `GLOBAL_METADATA_TRIE_DATA_SIZE`.
    PUSH 1
    PUSH @INITIAL_RLP_ADDR
    
global check_txn_trie:
    // stack: rlp_start, dummy_trie_len
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_AFTER)       %assert_eq
    PUSH @INITIAL_RLP_ADDR
global check_receipt_trie:
    // stack: rlp_start, dummy_trie_len
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_AFTER)   %assert_eq
global check_state_trie:
    // First, check initial trie.
    // We pop the dummy trie data length that was computed.
    POP 
    // Now, we get the trie data size so we can add the values from the 
    // initial trie data size and check that the value stored in 
    // `GLOBAL_METADATA_TRIE_DATA_SIZE` is correct.
    %get_trie_data_size
    // stack: trie_data_len
    PROVER_INPUT(trie_ptr::initial_state)

    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)

    PROVER_INPUT(trie_ptr::trie_data_size)
    %mstore_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)

    // stack: trie_data_len
    %set_initial_state_trie
    // stack: trie_data_len

    PUSH @INITIAL_RLP_ADDR
    // stack: rlp_start, trie_data_len
    %mpt_hash_state_trie

    // stack: init_state_hash, trie_data_len
    // Check that the initial trie is correct.
    %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE)
    %assert_eq
    // Check that the stored trie data length is correct.
    %mload_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)
    %assert_eq

    // We set a dummy value as an initial trie data length,
    // as we do not need to compute the actual trie data length here.
    PUSH 1
global check_final_state_trie:
    %set_final_tries
    PUSH @INITIAL_RLP_ADDR
    // stack: rlp_start, dummy_trie_len
    %mpt_hash_state_trie   %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_AFTER)     %assert_eq
    // We don't need the trie data length here.
    POP

    // We have reached the end of the execution, so we set the pruning flag to 1 for context 0.
    PUSH 1
    SET_CONTEXT
    
    %jump(halt)

%macro reinitialize_memory_pre_txn
    // Reinitialize accessed addresses and storage keys lists
    %init_access_lists
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_TOUCHED_ADDRESSES_LEN)

    // Reinitialize transient storage
    %init_transient_storage_len

    // Reinitialize global metadata
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_CONTRACT_CREATION)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_IS_PRECOMPILE_FROM_EOA)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_DATA_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_PAYLOAD_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_JOURNAL_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_JOURNAL_DATA_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_REFUND_COUNTER)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_SELFDESTRUCT_LIST_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_CREATED_CONTRACTS_LEN)

    // Reinitialize `chain_id` for legacy transactions and `to` transaction field
    PUSH 0 %mstore_txn_field(@TXN_FIELD_CHAIN_ID_PRESENT)
    PUSH 0 %mstore_txn_field(@TXN_FIELD_TO)

    #[cfg(feature = eth_mainnet)]
    {
        %reset_blob_versioned_hashes
    }
%endmacro
