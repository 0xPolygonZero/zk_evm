// BN254 elliptic curve scalar multiplication on the twist.
// Uses the naive algorithm.
global bn_twisted_mul:
    // stack: X: 2, Y: 2, s, retdest
    %dup_fp254_2_2
    // stack: Y, X, Y, s, retdest
    %dup_fp254_2_2
    // stack: X, Y, X, Y, s, retdest
    %bn_check_twisted_ident
    // stack: (X,Y)==(0,0), X, Y, s, retdest
    %jumpi(ret_zero_ec_twisted_mul)
    // stack: X, Y, s, retdest
    %dup_fp254_2_2
    // stack: Y, X, Y, s, retdest
    %dup_fp254_2_2
    // stack: X, Y, X, Y, s, retdest
    %bn_check_twisted
    // stack: isValid(X, Y), X, Y, s, retdest
    %jumpi(bn_twisted_mul_valid_point)
    // stack: X, Y, s, retdest
    %pop5
    %bn_twisted_invalid_input

bn_twisted_mul_valid_point:
    // stack: X, Y, s, retdest
    DUP5
    %num_bits
    // stack: n, X, Y, s, retdest
    %stack (n, X: 2, Y: 2, s, retdest) -> (X, Y, s, n, retdest)
    %rep 4
        PUSH 0 // identity point
    %endrep
bn_twisted_mul_loop:
    // stack: X', Y', X, Y, s, n, retdest
    DUP10
    ISZERO
    %jumpi(bn_twisted_mul_end)
    // stack: X1, Y1, X, Y, s, n, retdest
    %bn_twisted_double
    // stack: X2, Y2, X, Y, s, n, retdest
    DUP9
    // stack: s, X2, Y2, X, Y, s, n, retdest
    PUSH 1 DUP12 SUB
    // stack: n - 1, s, X2, Y2, X, Y, s, n, retdest
    SHR
    // stack: s >> n - 1, X2, Y2, X, Y, s, n, retdest
    PUSH 1
    AND
    // stack: nth_bit, X2, Y2, X, Y, s, n, retdest
    %jumpi(bn_twisted_mul_add_base)
    // stack: X2, Y2, X, Y, s, n, retdest
    SWAP9
    %decrement
    SWAP9
    // stack: X2, Y2, X, Y, s, n-1, retdest
    %jump(bn_twisted_mul_loop)

bn_twisted_mul_add_base:
    // stack: X2, Y2, X, Y, s, n, retdest
    %dup_fp254_2_6
    // stack: Y, X2, Y2, X, Y, s, n, retdest
    %dup_fp254_2_6
    // stack: X, Y, X2, Y2, X, Y, s, n, retdest
    %bn_twisted_add
    // stack: X3, Y3, X, Y, s, n, retdest
    SWAP9
    %decrement
    SWAP9
    // stack: X3, Y3, X, Y, s, n-1, retdest
    %jump(bn_twisted_mul_loop)

bn_twisted_mul_end:
    %stack (AX: 2, AY: 2, X: 2, Y: 2, s, n, retdest) -> (retdest, AX, AY)
    JUMP

// Convenience macro to call bn_twisted_mul and return where we left off.
%macro bn_twisted_mul
    %stack (X: 2, Y: 2, s) -> (X, Y, s, %%after)
    %jump(bn_twisted_mul)
%%after:
%endmacro


// G2 multiplication by z = -(2^62 + 2^55 + 1)
global bn_twisted_mul_by_z:
    // stack: X: 2, Y: 2, retdest
    %dup_fp254_2_2
    // stack: Y, X, Y, retdest
    %dup_fp254_2_2
    // stack: X, Y, X, Y, retdest
    %bn_check_twisted_ident
    // stack: (X,Y)==(0,0), X, Y, retdest
    %jumpi(ret_zero_ec_twisted_mul)
    // stack: X, Y, retdest
    %dup_fp254_2_2
    // stack: Y, X, Y, retdest
    %dup_fp254_2_2
    // stack: X, Y, X, Y, retdest
    %bn_check_twisted
    // stack: isValid(X, Y), X, Y, retdest
    %jumpi(bn_twisted_mul_by_z_valid_point)
    // stack: X, Y, retdest
    %pop4
    %bn_twisted_invalid_input
bn_twisted_mul_by_z_valid_point:
    // stack: X, Y, retdest
    %dup_fp254_2_2
    // stack: Y, X, Y, retdest
    %dup_fp254_2_2
    // stack: X, Y, X, Y, retdest

    // We start the accumulator at our base point,
    // equivalent of going through the naive scalar
    // multiplication up to the MSb of z included.
    %rep 7
        %bn_twisted_double
    %endrep

    // stack: AX, AY, X, Y, retdest
    %dup_fp254_2_6
    // stack: Y, AX, AY, X, Y, retdest
    %dup_fp254_2_6
    // stack: X, AX, AY, X, Y, retdest
    %bn_twisted_add // 55th bit

    %rep 55
        %bn_twisted_double
    %endrep

    // stack: AX, AY, X, Y, retdest
    %bn_twisted_add // LSb
    // stack: AX, AY, retdest
    
    // We need to output the opposite of the calculated point,
    // to account for the negative sign of z.
    %swap_fp254_2
    // stack: AY, AX, retdest
    PUSH 0 PUSH 0
    %sub_fp254_2
    // stack: -AY, AX, retdest
    %stack (AY: 2, AX: 2, retdest) -> (retdest, AX, AY)
    JUMP


// Convenience macro to call bn_twisted_mul_by_z and return where we left off.
%macro bn_twisted_mul_by_z
    %stack (X: 2, Y: 2) -> (X, Y, 0x44e992b44a6909f1, %%after)
    %jump(bn_twisted_mul)
%%after:
%endmacro
