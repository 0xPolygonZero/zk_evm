global init:
    PUSH @SEGMENT_REGISTERS_STATES
    // stack: addr_registers
    // First, set the registers correctly and verify their values.
    PUSH 2
    %stack_length SUB
    // stack: prev_stack_len, addr_registers
    // First, check the stack length.
    DUP1
    DUP3 %add_const(2) 
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
    DUP2 %increment
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
    // First, hash the kernel code
    // Start with PUSH0 to avoid having a BytePacking operation at timestamp 0.
    // Timestamp 0 is reserved for memory initialization.
    %mload_global_metadata(@GLOBAL_METADATA_KERNEL_LEN)
    PUSH 0
    // stack: addr, len
    KECCAK_GENERAL
    // stack: hash
    %mload_global_metadata(@GLOBAL_METADATA_KERNEL_HASH)
    // stack: expected_hash, hash
    %assert_eq

    // Initialize the RLP DATA pointer to its initial position, 
    // skipping over the preinitialized empty node.
    PUSH @INITIAL_TXN_RLP_ADDR
    %mstore_global_metadata(@GLOBAL_METADATA_RLP_DATA_SIZE)

    // Encode constant nodes
    %initialize_rlp_segment
   
    // Initialize the state, transaction and receipt trie root pointers.
    PROVER_INPUT(trie_ptr::state)
    %mstore_global_metadata(@GLOBAL_METADATA_STATE_TRIE_ROOT)
    PROVER_INPUT(trie_ptr::txn)
    %mstore_global_metadata(@GLOBAL_METADATA_TXN_TRIE_ROOT)
    PROVER_INPUT(trie_ptr::receipt)
    %mstore_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_ROOT)

global hash_initial_tries:
    // We compute the length of the trie data segment in `mpt_hash` so that we
    // can check the value provided by the prover.
    // We initialize the segment length with 1 because the segment contains 
    // the null pointer `0` when the tries are empty.
    PUSH 1
    %mpt_hash_state_trie  %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE)    %assert_eq
    // stack: trie_data_len
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_BEFORE)      %assert_eq
    // stack: trie_data_len
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_BEFORE)  %assert_eq
    // stack: trie_data_full_len
    %mstore_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)

global start_txns:
    // stack: (empty)
    // The special case of an empty trie (i.e. for the first transaction)
    // is handled outside of the kernel.
    %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_BEFORE)
    // stack: txn_nb
    DUP1 %scalar_to_rlp
    // stack: txn_counter, txn_nb
    DUP1 %num_bytes %mul_const(2)
    SWAP1
    // stack: txn_counter, num_nibbles, txn_nb
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_BEFORE)

    // stack: init_gas_used, txn_counter, num_nibbles, txn_nb
global txn_loop:
    // If the prover has no more txns for us to process, halt.
    PROVER_INPUT(end_of_txns)
    %jumpi(execute_withdrawals)

    // Initialize memory values.
    %initialize_memory_pre_txn
    
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
    SWAP3 %increment SWAP3

    // stack: new_cum_gas, txn_counter, num_nibbles, new_txn_number
    %jump(txn_loop)

global execute_withdrawals:
    // stack: cum_gas, txn_counter, num_nibbles, txn_nb
    %withdrawals

global perform_final_checks:
    // stack: cum_gas, txn_counter, num_nibbles, txn_nb
    // Check that we end up with the correct `cum_gas`, `txn_nb` and bloom filter.
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_AFTER) %assert_eq
    DUP3 %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_AFTER) %assert_eq
    %pop3
    PUSH 1 // initial trie data length
global check_state_trie:
    %mpt_hash_state_trie   %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_AFTER)     %assert_eq
global check_txn_trie:
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_AFTER)       %assert_eq
global check_receipt_trie:
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_AFTER)   %assert_eq
    // We don't need the trie data length here.
    POP
    %jump(halt)

%macro initialize_memory_pre_txn
    // Initialize accessed addresses and storage keys lists
    %init_access_lists

    // Initialize metadata
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_CONTRACT_CREATION)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_IS_PRECOMPILE_FROM_EOA)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_DATA_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_LOGS_PAYLOAD_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_JOURNAL_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_JOURNAL_DATA_LEN)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_REFUND_COUNTER)
    PUSH 0 %mstore_global_metadata(@GLOBAL_METADATA_SELFDESTRUCT_LIST_LEN)
%endmacro
