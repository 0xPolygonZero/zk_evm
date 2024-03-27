/// See `smt_trie::keys.rs` for documentation.

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_balance
    // stack: addr
    PUSH 0xffffffff
    // stack: u32max, addr
    DUP2 DUP2 AND
    // stack: a_0, u32max, addr
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %stack (y, u32max, x) -> (x, y, @POSEIDON_HASH_ZEROS)
    POSEIDON
%endmacro

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_nonce
    // stack: addr
    PUSH 0xffffffff
    // stack: u32max, addr
    DUP2 DUP2 AND
    // stack: a_0, u32max, addr
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %add_const(0x100000000000000000000000000000000) // SMT_KEY_NONCE (=1) << 128
    %stack (y, u32max, x) -> (x, y, @POSEIDON_HASH_ZEROS)
    POSEIDON
%endmacro

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_code
    // stack: addr
    PUSH 0xffffffff
    // stack: u32max, addr
    DUP2 DUP2 AND
    // stack: a_0, u32max, addr
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %add_const(0x200000000000000000000000000000000) // SMT_KEY_CODE (=2) << 128
    %stack (y, u32max, x) -> (x, y, @POSEIDON_HASH_ZEROS)
    POSEIDON
%endmacro

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_code_length
    // stack: addr
    PUSH 0xffffffff
    // stack: u32max, addr
    DUP2 DUP2 AND
    // stack: a_0, u32max, addr
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %add_const(0x400000000000000000000000000000000) // SMT_KEY_CODE_LENGTH (=4) << 128
    %stack (y, u32max, x) -> (x, y, @POSEIDON_HASH_ZEROS)
    POSEIDON
%endmacro

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_storage
    %stack (addr, slot) -> (slot, %%after, addr)
    %jump(hash_limbs)
%%after:
    // stack: capacity, addr
    SWAP1
    // stack: addr, capacity
    PUSH 0xffffffff
    // stack: u32max, addr, capacity
    DUP2 DUP2 AND
    // stack: a_0, u32max, addr
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %add_const(0x300000000000000000000000000000000) // SMT_KEY_STORAGE (=3) << 128
    %stack (y, u32max, x, capacity) -> (x, y, capacity)
    POSEIDON
%endmacro

// slot = sum_{0<=i<8} s_i << (32i)
global hash_limbs:
    // stack: slot, retdest
    PUSH 0xffffffff
    // stack: u32max, slot, retdest
    DUP2 DUP2 AND
    // stack: s_0, u32max, slot
    DUP3 %shr_const(32) DUP3 AND %shl_const(64) ADD
    // stack: s_0 + s_1<<64, u32max, slot
    DUP3 %shr_const(64) DUP3 AND %shl_const(128) ADD
    // stack: s_0 + s_1<<64 + s_2<<128, u32max, slot
    DUP3 %shr_const(96) DUP3 AND %shl_const(192) ADD
    // stack: s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP3 %shr_const(128) DUP3 AND
    // stack: s_4, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP4 %shr_const(160) DUP4 AND %shl_const(64) ADD
    // stack: s_4 + s_5<<64, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP4 %shr_const(192) DUP4 AND %shl_const(128) ADD
    // stack: s_4 + s_5<<64 + s_6<<128, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP4 %shr_const(224) DUP4 AND %shl_const(192) ADD
    // stack: s_4 + s_5<<64 + s_6<<128 + s_7<<192, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    %stack (b, a, u32max, slot) -> (a, b, 0)
    POSEIDON
    // stack: hash, retdest
    SWAP1 JUMP
