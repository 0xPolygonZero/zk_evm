%macro jump(dst)
    PUSH $dst
    jump
%endmacro

%macro jumpi(dst)
    PUSH $dst
    jumpi
%endmacro

// Jump to `jumpdest` if the top of the stack is != c
%macro jump_neq_const(c, jumpdest)
    PUSH $c
    SUB
    %jumpi($jumpdest)
%endmacro

// Jump to `jumpdest` if the top of the stack is < c
%macro jumpi_lt_const(c, jumpdest)
    %ge_const($c)
    %jumpi($jumpdest)
%endmacro

%macro pop2
    %rep 2
        POP
    %endrep
%endmacro

%macro pop3
    %rep 3
        POP
    %endrep
%endmacro

%macro pop4
    %rep 4
        POP
    %endrep
%endmacro

%macro pop5
    %rep 5
        POP
    %endrep
%endmacro

%macro pop6
    %rep 6
        POP
    %endrep
%endmacro

%macro pop7
    %rep 7
        POP
    %endrep
%endmacro

%macro pop8
    %rep 8
        POP
    %endrep
%endmacro

%macro pop9
    %rep 9
        POP
    %endrep
%endmacro

%macro pop10
    %rep 10
        POP
    %endrep
%endmacro

%macro and_const(c)
    // stack: input, ...
    PUSH $c
    AND
    // stack: input & c, ...
%endmacro

%macro add_const(c)
    // stack: input, ...
    PUSH $c
    ADD
    // stack: input + c, ...
%endmacro

// Slightly inefficient as we need to swap the inputs.
// Consider avoiding this in performance-critical code.
%macro sub_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    SWAP1
    // stack: input, c, ...
    SUB
    // stack: input - c, ...
%endmacro

%macro mul_const(c)
    // stack: input, ...
    PUSH $c
    MUL
    // stack: input * c, ...
%endmacro

// Slightly inefficient as we need to swap the inputs.
// Consider avoiding this in performance-critical code.
%macro div_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    SWAP1
    // stack: input, c, ...
    DIV
    // stack: input / c, ...
%endmacro

// Slightly inefficient as we need to swap the inputs.
// Consider avoiding this in performance-critical code.
%macro mod_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    SWAP1
    // stack: input, c, ...
    MOD
    // stack: input % c, ...
%endmacro

%macro shl_const(c)
    // stack: input, ...
    PUSH $c
    SHL
    // stack: input << c, ...
%endmacro

%macro shr_const(c)
    // stack: input, ...
    PUSH $c
    SHR
    // stack: input >> c, ...
%endmacro

%macro eq_const(c)
    // stack: input, ...
    PUSH $c
    EQ
    // stack: input == c, ...
%endmacro

%macro lt_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    GT // Check it backwards: (input < c) == (c > input)
    // stack: input < c, ...
%endmacro

%macro le_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    LT ISZERO // Check it backwards: (input <= c) == !(c < input)
    // stack: input <= c, ...
%endmacro

%macro gt_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    LT // Check it backwards: (input > c) == (c < input)
    // stack: input >= c, ...
%endmacro

%macro ge_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    GT ISZERO // Check it backwards: (input >= c) == !(c > input)
    // stack: input >= c, ...
%endmacro

// If pred is zero, yields z; otherwise, yields nz
%macro select
    // stack: pred, nz, z
    ISZERO
    // stack: pred == 0, nz, z
    DUP1
    // stack: pred == 0, pred == 0, nz, z
    ISZERO
    // stack: pred != 0, pred == 0, nz, z
    SWAP3
    // stack: z, pred == 0, nz, pred != 0
    MUL
    // stack: (pred == 0) * z, nz, pred != 0
    SWAP2
    // stack: pred != 0, nz, (pred == 0) * z
    MUL
    // stack: (pred != 0) * nz, (pred == 0) * z
    ADD
    // stack: (pred != 0) * nz + (pred == 0) * z
%endmacro

// If pred, yields x; otherwise, yields y
// Assumes pred is boolean (either 0 or 1).
%macro select_bool
    // stack: pred, y, x
    DUP1
    // stack: pred, pred, y, x
    ISZERO
    // stack: notpred, pred, y, x
    SWAP3
    // stack: x, pred, y, notpred
    MUL
    // stack: pred * x, y, notpred
    SWAP2
    // stack: notpred, y, pred * x
    MUL
    // stack: notpred * y, pred * x
    ADD
    // stack: notpred * y + pred * x
%endmacro

%macro square
    // stack: x
    DUP1
    // stack: x, x
    MUL
    // stack: x^2
%endmacro

%macro min
    // stack: x, y
    DUP2
    DUP2
    // stack: x, y, x, y
    GT
    // stack: x > y, x, y
    %select_bool
    // stack: min
%endmacro

%macro max
    // stack: x, y
    DUP2
    DUP2
    // stack: x, y, x, y
    LT
    // stack: x < y, x, y
    %select_bool
    // stack: max
%endmacro

%macro max_3
    // stack: x, y, z
    %max
    // stack: max(x, y), z
    SWAP1
    // stack: z, max(x, y)
    %max
    // stack: max(x, y, z)
%endmacro

%macro max_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    %max
    // stack: max(input, c), ...
%endmacro

%macro min_const(c)
    // stack: input, ...
    PUSH $c
    // stack: c, input, ...
    %min
    // stack: min(input, c), ...
%endmacro

%macro ceil_div
    // stack: x, y
    PUSH 1
    DUP3
    SUB // y - 1
    // stack: y - 1, x, y
    ADD
    DIV
    // stack: ceil(x / y)
%endmacro

%macro ceil_div_const(c)
    // stack: x, ...
    PUSH $c
    // stack: c, x, ...
    SWAP1
    // stack: x, c, ...
    %ceil_div
    // stack: ceil(x / c), ...
%endmacro

// Same as `%as_u32`, but does not rely on
// the AND operation.
// *Note*: This is heavier, `%as_u32` should be preferred.
%macro as_u32_no_and
    // stack: word
    PUSH 0x100000000
    SWAP1
    MOD
%endmacro

%macro as_u32
    %and_const(0xffffffff)
%endmacro

%macro as_u64
    %and_const(0xffffffffffffffff)
%endmacro

%macro not_u32
    // stack: x
    PUSH 0xffffffff
    // stack: 0xffffffff, x
    SUB
    // stack: 0xffffffff - x
%endmacro

// u32 addition (discarding 2^32 bit)
%macro add_u32
    // stack: x, y
    ADD
    // stack: x + y
    %as_u32
    // stack: (x + y) & u32::MAX
%endmacro

%macro add3_u32
    // stack: x , y , z
    ADD
    // stack: x + y , z
    ADD
    // stack: x + y + z
    %as_u32
%endmacro

%macro increment
    %add_const(1)
%endmacro

%macro decrement
    %sub_const(1)
%endmacro

%macro div2
    // stack: x
    PUSH 1
    SHR
    // stack: x >> 1
%endmacro

%macro iseven
    %mod_const(2)
    ISZERO
%endmacro

// given u32 bytestring abcd return dcba
%macro reverse_bytes_u32
    // stack:              abcd
    DUP1
    PUSH 28
    BYTE
    // stack:           a, abcd
    DUP2
    PUSH 29
    BYTE
    %shl_const(8)
    // stack:       b0, a, abcd 
    DUP3
    PUSH 30
    BYTE
    %shl_const(16)
    // stack:  c00, b0, a, abcd
    SWAP3
    PUSH 31
    BYTE
    %shl_const(24)
    // stack:  d000, b0, a, c00
    ADD // OR
    ADD // OR
    ADD // OR
    // stack:              dcba
%endmacro

%macro reverse_bytes_u64
    // stack: word
    DUP1
    // stack: word, word
    %and_const(0xffffffff)
    // stack: word_lo, word
    SWAP1
    // stack: word, word_lo
    %shr_const(32)
    // stack: word_hi, word_lo
    %reverse_bytes_u32
    // stack: word_hi_inverted, word_lo
    SWAP1
    // stack: word_lo, word_hi_inverted
    %reverse_bytes_u32
    // stack: word_lo_inverted, word_hi_inverted
    %shl_const(32)
    ADD // OR
    // stack: word_inverted
%endmacro

// Combine four big-endian u64s into a u256.
%macro u64s_to_u256
    // stack: a, b, c, d
    %rep 3
        %shl_const(64)
        ADD // OR
    %endrep
    // stack: a || b || c || d
%endmacro

%macro u256_to_addr
    // stack: x
    %mod_const(0x10000000000000000000000000000000000000000) // 2^160
%endmacro

%macro not_bit
    // stack: b
    ISZERO
    // stack: not b
%endmacro

%macro build_address
    // stack: ctx, seg, off
    ADD
    ADD
    // stack: addr
%endmacro

%macro build_address_no_offset
    // stack: ctx, seg
    ADD
    // stack: addr
%endmacro

%macro build_current_general_address
    // stack: offset
    PUSH @SEGMENT_KERNEL_GENERAL
    GET_CONTEXT
    %build_address
    // stack: addr
%endmacro

%macro build_current_general_address_no_offset
    // stack:
    PUSH @SEGMENT_KERNEL_GENERAL
    GET_CONTEXT
    %build_address_no_offset
    // stack: addr (offset == 0)
%endmacro

%macro build_kernel_address
    // stack: seg, off
    ADD
    // stack: addr (ctx == 0)
%endmacro

%macro build_address_with_ctx(seg, off)
    // stack: ctx
    PUSH $seg
    PUSH $off
    %build_address
    // stack: addr
%endmacro

%macro build_address_with_ctx_no_offset(seg)
    // stack: ctx
    PUSH $seg
    ADD
    // stack: addr
%endmacro

%macro build_address_with_ctx_no_segment(off)
    // stack: ctx
    PUSH $off
    ADD
    // stack: addr
%endmacro
