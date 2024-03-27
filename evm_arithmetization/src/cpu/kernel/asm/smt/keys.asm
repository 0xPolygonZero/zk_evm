/// See `smt_trie::keys.rs` for documentation.

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_balance
    // stack: addr
    PUSH 0x100000000
    // stack: u32max, addr
    DUP1 DUP3 MOD
    // stack: a_0, u32max, addr
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
    // stack: a_0 + a_1<<64 + a_2<<128 + a_3<<192, u32max, addr
    SWAP2 %shr_const(128)
    // stack: a_4, u32max, a_0 + a_1<<64 + a_2<<128 + a_3<<192
    %stack (y, u32max, x) -> (x, y, @POSEIDON_HASH_ZEROS)
    POSEIDON
%endmacro

// addr = sum_{0<=i<5} a_i << (32i)
%macro key_nonce
    // stack: addr
    PUSH 0x100000000
    // stack: u32max, addr
    DUP1 DUP3 MOD
    // stack: a_0, u32max, addr
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
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
    PUSH 0x100000000
    // stack: u32max, addr
    DUP1 DUP3 MOD
    // stack: a_0, u32max, addr
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
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
    PUSH 0x100000000
    // stack: u32max, addr
    DUP1 DUP3 MOD
    // stack: a_0, u32max, addr
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
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
    PUSH 0x100000000
    // stack: u32max, addr, capacity
    DUP1 DUP3 MOD
    // stack: a_0, u32max, addr
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: a_0 + a_1<<64, u32max, addr
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: a_0 + a_1<<64 + a_2<<128, u32max, addr
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
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
    PUSH 0x100000000
    // stack: u32max, slot, retdest
    DUP1 DUP3 MOD
    // stack: s_0, u32max, slot
    DUP2 DUP4 %shr_const(32) MOD %shl_const(64) ADD
    // stack: s_0 + s_1<<64, u32max, slot
    DUP2 DUP4 %shr_const(64) MOD %shl_const(128) ADD
    // stack: s_0 + s_1<<64 + s_2<<128, u32max, slot
    DUP2 DUP4 %shr_const(96) MOD %shl_const(192) ADD
    // stack: s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP2 DUP4 %shr_const(128) MOD
    // stack: s_4, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP3 DUP5 %shr_const(160) MOD %shl_const(64) ADD
    // stack: s_4 + s_5<<64, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP3 DUP5 %shr_const(192) MOD %shl_const(128) ADD
    // stack: s_4 + s_5<<64 + s_6<<128, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    DUP3 DUP5 %shr_const(224) MOD %shl_const(192) ADD
    // stack: s_4 + s_5<<64 + s_6<<128 + s_7<<192, s_0 + s_1<<64 + s_2<<128 + s_3<<192, u32max, slot
    %stack (b, a, u32max, slot) -> (a, b, 0)
    POSEIDON
    // stack: hash, retdest
    SWAP1 JUMP
