// Create a smart contract account with the given address and the given endowment value.
// Pre stack: address
// Post stack: status
%macro create_contract_account
    // stack: address
    DUP1 %insert_touched_addresses
    DUP1 %append_created_contracts
    DUP1 %read_code ISZERO %jumpi(%%add_account)
    // Check that the nonce is 0.
    // stack: address
    DUP1 %nonce
    // stack: nonce, address
    %jumpi(%%error_collision)
    // stack: address
    // Check that the code is empty.
    DUP1 %extcodehash
    %eq_const(@EMPTY_STRING_POSEIDON_HASH) ISZERO %jumpi(%%error_collision)
    DUP1 %balance
    %jump(%%do_insert)

    %%add_account:
        // stack: address
        DUP1 PUSH 1
        // stack: is_contract, address, address
        %journal_add_account_created
        // stack: address
        PUSH 0
    %%do_insert:
        // stack: new_acct_value, address
        // Write the new account's data to MPT data, and get a pointer to it.
        // stack: new_acct_value, address
        PUSH 0 DUP3 %journal_add_nonce_change
        %stack (new_acct_value, address) -> (address, 1, new_acct_value, address)
        %set_nonce // nonce = 1
        // stack: new_acct_value, address
        DUP2 %set_balance // balance = new_acct_value
        %stack (address) -> (address, @EMPTY_STRING_POSEIDON_HASH)
        %set_code
        // stack: empty
        PUSH 0 // success
        %jump(%%end)
    
    // If the nonce is nonzero or the code is non-empty, that means a contract has already been deployed to this address.
    // (This should be impossible with contract creation transactions or CREATE, but possible with CREATE2.)
    // So we return 1 to indicate an error.
    %%error_collision:
                %stack (address) -> (1)
    %%end:
                // stack: status
%endmacro

%macro append_created_contracts
    // stack: address
    %mload_global_metadata(@GLOBAL_METADATA_CREATED_CONTRACTS_LEN)
    // stack: nb_created_contracts, address
    SWAP1 DUP2
    // stack: nb_created_contracts, address, nb_created_contracts
    %mstore_kernel(@SEGMENT_CREATED_CONTRACTS)
    // stack: nb_created_contracts
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_CREATED_CONTRACTS_LEN)
%endmacro
