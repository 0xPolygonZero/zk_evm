global main:
    // First, hash the kernel code
    %mload_global_metadata(@GLOBAL_METADATA_KERNEL_LEN)
    PUSH 0
    // stack: addr, len
    KECCAK_GENERAL
    // stack: hash
    %mload_global_metadata(@GLOBAL_METADATA_KERNEL_HASH)
    // stack: expected_hash, hash
    %assert_eq

    // Initialise the shift table
    %shift_table_init

    // Initialize accessed addresses and storage keys lists
    %init_access_lists

    // Initialize the RLP DATA pointer to its initial position, 
    // skipping over the preinitialized empty node.
    PUSH @INITIAL_TXN_RLP_ADDR
    %mstore_global_metadata(@GLOBAL_METADATA_RLP_DATA_SIZE)

    // Encode constant nodes
    %initialize_rlp_segment

    // Initialize linked list and trie data constants.
    // TODO: Validate them.
    PROVER_INPUT(linked_list::accounts_linked_list_len)
    %mstore_global_metadata(@GLOBAL_METADATA_ACCOUNTS_LINKED_LIST_LEN)
    PROVER_INPUT(linked_list::storage_linked_list_len)
    %mstore_global_metadata(@GLOBAL_METADATA_STORAGE_LINKED_LIST_LEN)
    PROVER_INPUT(trie_ptr::trie_data_size)
    %mstore_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)
   
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
    // The trie data segment is already written by the linked lists
    %mload_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)

    %set_initial_tries
    %mpt_hash_state_trie  %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_BEFORE)
    global debug_check_hash_after_setting_payloads:
    %assert_eq


    // stack: trie_data_len
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_BEFORE)      %assert_eq
    // stack: trie_data_len
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_BEFORE)  %assert_eq
    // stack: trie_data_full_len

    %mstore_global_metadata(@GLOBAL_METADATA_TRIE_DATA_SIZE)

global start_txn:
    // stack: (empty)
    // The special case of an empty trie (i.e. for the first transaction)
    // is handled outside of the kernel.
    %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_BEFORE)
    // stack: txn_nb
    DUP1 %scalar_to_rlp
    // stack: txn_counter, txn_nb
    DUP1 %num_bytes %mul_const(2)
    // stack: num_nibbles, txn_counter, txn_nb
    %increment_bounded_rlp
    // stack: txn_counter, num_nibbles, next_txn_counter, next_num_nibbles,  txn_nb
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_BEFORE)

    // stack: init_gas_used, txn_counter, num_nibbles, next_txn_counter, next_num_nibbles, txn_nb

    // If the prover has no txn for us to process, halt.
    PROVER_INPUT(no_txn)
    %jumpi(execute_withdrawals)

    // Call route_txn. When we return, we will process the txn receipt.
    PUSH txn_after
    // stack: retdest, prev_gas_used, txn_counter, num_nibbles, next_txn_counter, next_num_nibbles, txn_nb
    DUP4 DUP4

    %jump(route_txn)

global txn_after:
    // stack: success, leftover_gas, cur_cum_gas, prev_txn_counter, prev_num_nibbles, txn_counter, num_nibbles, txn_nb
    %process_receipt
    // stack: new_cum_gas, txn_counter, num_nibbles, txn_nb
    SWAP3 %increment SWAP3
    %jump(execute_withdrawals_post_stack_op)

global execute_withdrawals:
    // stack: cum_gas, txn_counter, num_nibbles, next_txn_counter, next_num_nibbles, txn_nb
    %stack (cum_gas, txn_counter, num_nibbles, next_txn_counter, next_num_nibbles) -> (cum_gas, txn_counter, num_nibbles)
execute_withdrawals_post_stack_op:
    %withdrawals

global perform_final_checks:
    // stack: cum_gas, txn_counter, num_nibbles, txn_nb
    // Check that we end up with the correct `cum_gas`, `txn_nb` and bloom filter.
    %mload_global_metadata(@GLOBAL_METADATA_BLOCK_GAS_USED_AFTER) 
global debug_check_gas:
    %assert_eq

    
    DUP3 %mload_global_metadata(@GLOBAL_METADATA_TXN_NUMBER_AFTER)
global debug_check_txn_number:
    %assert_eq
    %pop3
    PUSH 1 // initial trie data length
    
global check_state_trie:
    %set_final_tries
    %mpt_hash_state_trie   %mload_global_metadata(@GLOBAL_METADATA_STATE_TRIE_DIGEST_AFTER)     
global debug_check_final_trie:
    %assert_eq
global check_txn_trie:
    %mpt_hash_txn_trie     %mload_global_metadata(@GLOBAL_METADATA_TXN_TRIE_DIGEST_AFTER)       %assert_eq
global check_receipt_trie:
    %mpt_hash_receipt_trie %mload_global_metadata(@GLOBAL_METADATA_RECEIPT_TRIE_DIGEST_AFTER)   %assert_eq
    // We don't need the trie data length here.
    POP
    %jump(halt)
