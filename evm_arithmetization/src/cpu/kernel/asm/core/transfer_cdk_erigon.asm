// Transfers some ETH from one address to another. The amount is given in wei.
// Pre stack: from, to, amount, retdest
// Post stack: status (0 indicates success)
global transfer_eth:
    // stack: from, to, amount, retdest
    %stack (from, to, amount, retdest)
        -> (from, amount, to, amount, retdest)
    %deduct_eth
    // stack: deduct_eth_status, to, amount, retdest
    %jumpi(transfer_eth_failure)
    // stack: to, amount, retdest
    %add_eth
    %stack (retdest) -> (retdest, 0)
    JUMP
global transfer_eth_failure:
    %stack (to, amount, retdest) -> (retdest, 1)
    JUMP

// Convenience macro to call transfer_eth and return where we left off.
%macro transfer_eth
    %stack (from, to, amount) -> (from, to, amount, %%after)
    %jump(transfer_eth)
%%after:
%endmacro

// Returns 0 on success, or 1 if addr has insufficient balance. Panics if addr isn't found in the trie.
// Pre stack: addr, amount, retdest
// Post stack: status (0 indicates success)
global deduct_eth:
    // stack: addr, amount, retdest
    DUP1 %insert_touched_addresses
    DUP2 ISZERO %jumpi(deduct_eth_noop)
    DUP1 %read_balance
    // stack: balance, addr, amount, retdest
    // stack: balance, addr, amount, retdest
    DUP1 DUP4 GT
    // stack: amount > balance, balance, addr, amount, retdest
    %jumpi(deduct_eth_insufficient_balance)
    // stack: balance, addr, amount, retdest
    DUP1 DUP4 EQ
    // stack: amount == balance, balance, addr, amount, retdest
    %jumpi(deduct_eth_delete_balance)
    %stack (balance, addr, amount, retdest) -> (balance, amount, addr, retdest, 0)
    SUB
    SWAP1
    // stack: addr, balance - amount, retdest, 0
    %set_balance
    // stack: retdest, 0
    JUMP
deduct_eth_insufficient_balance:
    %stack (balance, addr, amount, retdest) -> (retdest, 1)
    JUMP
deduct_eth_delete_balance:
    %stack (balance, addr, amount, retdest) -> (addr, retdest, 0)
    %remove_balance
    // stack: retdest, 0
    JUMP
deduct_eth_noop:
    %stack (addr, amount, retdest) -> (retdest, 0)
    JUMP

// Convenience macro to call deduct_eth and return where we left off.
%macro deduct_eth
    %stack (addr, amount) -> (addr, amount, %%after)
    %jump(deduct_eth)
%%after:
%endmacro

// Pre stack: addr, amount, redest
// Post stack: (empty)
global add_eth:
    // stack: addr, amount, retdest
    DUP1 %insert_touched_addresses
    DUP2 ISZERO %jumpi(add_eth_noop)
    // stack: addr, amount, retdest
    DUP1 %read_code
    // stack: codehash, addr, amount, retdest
    ISZERO %jumpi(add_eth_new_account) // If the account is empty, we need to create the account.
    // stack: addr, amount, retdest
    %key_balance
    // stack: key_balance, amount
    DUP1 %search_key // TODO: replace with read_balance?
    DUP1 ISZERO %jumpi(add_eth_zero_balance)
    %stack (balance, key_balance, amount) -> (balance, amount, key_balance)
    // stack: balance, amount, key_balance, retdest
    ADD
    // stack: balance+amount, key_balance, retdest
    SWAP1 %insert_key
    JUMP
add_eth_zero_balance:
    // stack: balance, key_balance, amount, retdest
    POP
    // stack: key_balance, amount, retdest
    %insert_key // TODO: replace with set_balance?
    // stack: retdest
    JUMP

global add_eth_new_account:
    // stack: addr, amount, retdest
    DUP1 PUSH 0
    // stack: is_eoa, addr, amount, retdest
    %journal_add_account_created
    // stack: addr, amount, retdest
    DUP1 %key_code
    %stack (key_code) -> (key_code, @EMPTY_STRING_POSEIDON_HASH)
    %insert_key // TODO: replace with set_code?
    // stack: addr, amount, retdest
    %set_balance
    JUMP

add_eth_noop:
    // stack: addr, amount, retdest
    %pop2 JUMP

// Convenience macro to call add_eth and return where we left off.
%macro add_eth
    %stack (addr, amount) -> (addr, amount, %%after)
    %jump(add_eth)
%%after:
%endmacro
