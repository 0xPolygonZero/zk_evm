// Given an address, return a pointer to the associated account data, which
// consists of four words (nonce, balance, storage_root, code_hash), in the
// trie_data segment. Return null if the address is not found.
global read_state_trie:
    // stack: addr, retdest
    %read_accounts_linked_list
    // stack: account_ptr, retdest
    SWAP1
    // stack: retdest, account_ptr
    JUMP

// Convenience macro to call read_state_trie and return where we left off.
%macro read_state_trie
    %stack (addr) -> (addr, %%after)
    %jump(read_state_trie)
%%after:
%endmacro

// Mutate the state trie linked list, inserting the given key-value pair.
// Pre stack: key, value_ptr, retdest
// Post stack: (empty)
// TODO: Have this take an address and do %insert_state_trie? To match read_state_trie.
global insert_state_trie:
    // stack: key, value_ptr, retdest
    %insert_account_with_overwrite
    JUMP

%macro insert_state_trie
    %stack (key, value_ptr) -> (key, value_ptr, %%after)
    %jump(insert_state_trie)
%%after:
%endmacro