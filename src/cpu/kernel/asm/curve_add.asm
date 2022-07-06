// #define N 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 // BN254 base field order

global ec_add:
    // Uncomment for test inputs.
    // PUSH 0xdeadbeef
    // PUSH 2
    // PUSH 1
    // PUSH 0x1bf9384aa3f0b3ad763aee81940cacdde1af71617c06f46e11510f14f3d5d121
    // PUSH 0xe7313274bb29566ff0c8220eb9841de1d96c2923c6a4028f7dd3c6a14cee770
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest
    DUP2
    // stack: y0, x0, y0, x1, y1, retdest
    DUP2
    // stack: x0, y0, x0, y0, x1, y1, retdest
    %ec_check
    // stack: isValid(x0, y0), x0, y0, x1, y1, retdest
    DUP5
    // stack: x1, isValid(x0, y0), x0, y0, x1, y1, retdest
    DUP5
    // stack: x1, y1, isValid(x0, y0), x0, y0, x1, y1, retdest
    %ec_check
    // stack: isValid(x1, y1), isValid(x0, y0), x0, y0, x1, y1, retdest
    AND
    // stack: isValid(x1, y1) & isValid(x0, y0), x0, y0, x1, y1, retdest
    PUSH ec_add_valid_points
    // stack: ec_add_valid_points, isValid(x1, y1) & isValid(x0, y0), x0, y0, x1, y1, retdest
    JUMPI
    // stack: x0, y0, x1, y1, retdest
    POP
    // stack: y0, x1, y1, retdest
    POP
    // stack: x1, y1, retdest
    POP
    // stack: y1, retdest
    POP
    // stack: retdest
    %ec_invalid_input

// Assumption: (x0,y0) and (x1,y1) are valid points.
global ec_add_valid_points:
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest
    DUP2
    // stack: y0, x0, y0, x1, y1, retdest
    DUP2
    // stack: x0, y0, x0, y0, x1, y1, retdest
    %ec_isidentity
    // stack: (x0,y0)==(0,0), x0, y0, x1, y1, retdest
    PUSH ec_add_first_zero
    // stack: ec_add_first_zero, y0==0 & x0==0, x0, y0, x1, y1, retdest
    JUMPI
    // stack: x0, y0, x1, y1, retdest
    DUP4
    // stack: y1, x0, y0, x1, y1, retdest
    DUP4
    // stack: x1, y1, x0, y0, x1, y1, retdest
    %ec_isidentity
    // stack: (x1,y1)==(0,0), x0, y0, x1, y1, retdest
    PUSH ec_add_snd_zero
    // stack: ec_add_snd_zero, y1==0 & x1==0, x0, y0, x1, y1, retdest
    JUMPI
    // stack: x0, y0, x1, y1, retdest
    DUP3
    // stack: x1, x0, y0, x1, y1, retdest
    DUP2
    // stack: x0, x1, x0, y0, x1, y1, retdest
    EQ
    // stack: x0 == x1, x0, y0, x1, y1, retdest
    PUSH ec_add_equal_first_coord
    // stack: ec_add_equal_first_coord, x0 == x1, x0, y0, x1, y1, retdest
    JUMPI
    // stack: x0, y0, x1, y1, retdest
    DUP4
    // stack: y1, x0, y0, x1, y1, retdest
    DUP3
    // stack: y0, y1, x0, y0, x1, y1, retdest
    %submod
    // stack: y0 - y1, x0, y0, x1, y1, retdest
    DUP4
    // stack: x1, y0 - y1, x0, y0, x1, y1, retdest
    DUP3
    // stack: x0, x1, y0 - y1, x0, y0, x1, y1, retdest
    %submod
    // stack: x0 - x1, y0 - y1, x0, y0, x1, y1, retdest
    %moddiv
    // stack: lambda, x0, y0, x1, y1, retdest
    PUSH ec_add_valid_points_with_lambda
    // stack: ec_add_valid_points_with_lambda, lambda, x0, y0, x1, y1, retdest
    JUMP

// Assumption: (x0,y0) == (0,0)
ec_add_first_zero:
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest
    POP
    // stack: y0, x1, y1, retdest
    POP
    // stack: x1, y1, retdest
    DUP2
    // stack: y1, x1, y1, retdest
    DUP2
    // stack: x1, y1, x1, y1, retdest
    %ec_isidentity
    // stack: (x1,y1)==(0,0), x1, y1, retdest
    PUSH ret_zero
    // stack: ret_zero, (x1,y1)==(0,0), x1, y1, retdest
    JUMPI
    // stack: x1, y1, retdest
    SWAP1
    // stack: y1, x1, retdest
    SWAP2
    // stack: retdest, x1, y1
    JUMP

// Assumption: (x1,y1) == (0,0) and (x0,y0) != (0,0)
ec_add_snd_zero:
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest
    SWAP2
    // stack: x1, y0, x0, y1, retdest
    POP
    // stack: y0, x0, y1, retdest
    SWAP2
    // stack: y1, x0, y0, retdest
    POP
    // stack: x0, y0, retdest
    SWAP1
    // stack: y0, x0, retdest
    SWAP2
    // stack: retdest, x0, y0
    JUMP

ret_zero:
    JUMPDEST
    // stack: x, y, retdest
    POP
    // stack: y, retdest
    POP
    // stack: retdest
    PUSH 0
    // stack: 0, retdest
    PUSH 0
    // stack: 0, 0, retdest
    SWAP2
    // stack:  retdest, 0, 0
    JUMP

ec_add_valid_points_with_lambda:
    JUMPDEST
    // stack: lambda, x0, y0, x1, y1, retdest
    DUP2
    // stack: x0, lambda, x0, y0, x1, y1, retdest
    DUP5
    // stack: x1, x0, lambda, x0, y0, x1, y1, retdest
    %bn_base
    // stack: N, x1, x0, lambda, x0, y0, x1, y1, retdest
    DUP4
    // stack: lambda, N, x1, x0, lambda, x0, y0, x1, y1, retdest
    DUP1
    // stack: lambda, lambda, N, x1, x0, lambda, x0, y0, x1, y1, retdest
    MULMOD
    // stack: lambda^2, x1, x0, lambda, x0, y0, x1, y1, retdest
    %submod
    // stack: lambda^2 - x1, x0, lambda, x0, y0, x1, y1, retdest
    %submod
    // stack: x2, lambda, x0, y0, x1, y1, retdest
    %bn_base
    // stack: N, x2, lambda, x0, y0, x1, y1, retdest
    DUP2
    // stack: x2, N, x2, lambda, x0, y0, x1, y1, retdest
    DUP7
    // stack: x1, x2, N, x2, lambda, x0, y0, x1, y1, retdest
    %submod
    // stack: x1 - x2, N, x2, lambda, x0, y0, x1, y1, retdest
    DUP4
    // stack: lambda, x1 - x2, N, x2, lambda, x0, y0, x1, y1, retdest
    MULMOD
    // stack: lambda * (x1 - x2), x2, lambda, x0, y0, x1, y1, retdest
    DUP7
    // stack: y1, lambda * (x1 - x2), x2, lambda, x0, y0, x1, y1, retdest
    SWAP1
    // stack: lambda * (x1 - x2), y1, x2, lambda, x0, y0, x1, y1, retdest
    %submod
    // stack: y2, x2, lambda, x0, y0, x1, y1, retdest
    SWAP5
    // stack: x1, x2, lambda, x0, y0, y2, y1, retdest
    POP
    // stack: x2, lambda, x0, y0, y2, y1, retdest
    SWAP5
    // stack: y1, lambda, x0, y0, y2, x2, retdest
    POP
    // stack: lambda, x0, y0, y2, x2, retdest
    POP
    // stack: x0, y0, y2, x2, retdest
    POP
    // stack: y0, y2, x2, retdest
    POP
    // stack: y2, x2, retdest
    SWAP2
    // stack: retdest, x2, y2
    JUMP

// Assumption: (x0,y0) and (x1,y1) are valid points and x0 == x1
ec_add_equal_first_coord:
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest with x0 == x1
    %bn_base
    // stack: N, x0, y0, x1, y1, retdest
    DUP3
    // stack: y0, N, x0, y0, x1, y1, retdest
    DUP6
    // stack: y1, y0, N, x0, y0, x1, y1, retdest
    ADDMOD
    // stack: y1 + y0, x0, y0, x1, y1, retdest
    PUSH ec_add_equal_points
    // stack: ec_add_equal_points, y1 + y0, x0, y0, x1, y1, retdest
    JUMPI
    // stack: x0, y0, x1, y1, retdest
    POP
    // stack: y0, x1, y1, retdest
    POP
    // stack: x1, y1, retdest
    PUSH ret_zero
    // stack: ret_zero, x1, y1, retdest
    JUMP


// Assumption: x0 == x1 and y0 == y1
ec_add_equal_points:
    JUMPDEST
    // stack: x0, y0, x1, y1, retdest
    %bn_base
    // stack: N, x0, y0, x1, y1, retdest
    %bn_base
    // stack: N, N, x0, y0, x1, y1, retdest
    DUP3
    // stack: x0, N, N, x0, y0, x1, y1, retdest
    DUP1
    // stack: x0, x0, N, N, x0, y0, x1, y1, retdest
    MULMOD
    // stack: x0^2, N, x0, y0, x1, y1, retdest with
    PUSH 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea5 // 3/2 in the base field
    // stack: 3/2, x0^2, N, x0, y0, x1, y1, retdest
    MULMOD
    // stack: 3/2 * x0^2, x0, y0, x1, y1, retdest
    DUP3
    // stack: y0, 3/2 * x0^2, x0, y0, x1, y1, retdest
    %moddiv
    // stack: lambda, x0, y0, x1, y1, retdest
    PUSH ec_add_valid_points_with_lambda
    // stack: ec_add_valid_points_with_lambda, lambda, x0, y0, x1, y1, retdest
    JUMP

// Assumption: (x0,y0) is a valid point.
global ec_double:
    JUMPDEST
    // stack: x0, y0, retdest
    DUP2
    // stack: y0, x0, y0, retdest
    DUP2
    // stack: x0, y0, x0, y0, retdest
    PUSH ec_add_equal_points
    // stack: ec_add_equal_points, x0, y0, x0, y0, retdest
    JUMP

// Push the order of the BN254 base field.
%macro bn_base
    PUSH 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
%endmacro

// Assumption: x, y < N and 2N < 2^256.
// Note: Doesn't hold for Secp256k1 base field.
%macro submod
    // stack: x, y
    %bn_base
    // stack: N, x, y
    ADD
    // stack: N + x, y // Doesn't overflow since 2N < 2^256
    SUB
    // stack: N + x - y // Doesn't underflow since y < N
    %bn_base
    // stack: N, N + x - y
    SWAP1
    // stack: N + x - y, N
    MOD
    // stack: (N + x - y) % N = (x-y) % N
%endmacro

// Check if (x,y) is a valid curve point.
// Puts y^2 % N == (x^3 + 3) % N & (x < N) & (y < N) || (x,y)==(0,0) on top of the stack.
%macro ec_check
    // stack: x, y
    %bn_base
    // stack: N, x, y
    DUP2
    // stack: x, N, x, y
    LT
    // stack: x < N, x, y
    %bn_base
    // stack: N, x < N, x, y
    DUP4
    // stack: y, N, x < N, x, y
    LT
    // stack: y < N, x < N, x, y
    AND
    // stack: (y < N) & (x < N), x, y
    SWAP2
    // stack: y, x, (y < N) & (x < N), x
    SWAP1
    // stack: x, y, (y < N) & (x < N)
    %bn_base
    // stack: N, x, y, b
    %bn_base
    // stack: N, N, x, y, b
    DUP3
    // stack: x, N, N, x, y, b
    %bn_base
    // stack: N, x, N, N, x, y, b
    DUP2
    // stack: x, N, x, N, N, x, y, b
    DUP1
    // stack: x, x, N, x, N, N, x, y, b
    MULMOD
    // stack: x^2 % N, x, N, N, x, y, b
    MULMOD
    // stack: x^3 % N, N, x, y, b
    PUSH 3
    // stack: 3, x^3 % N, N, x, y, b
    ADDMOD
    // stack: (x^3 + 3) % N, x, y, b
    DUP3
    // stack: y, (x^3 + 3) % N, x, y, b
    %bn_base
    // stack: N, y, (x^3 + 3) % N, x, y, b
    SWAP1
    // stack: y, N, (x^3 + 3) % N, x, y, b
    DUP1
    // stack: y, y, N, (x^3 + 3) % N, x, y, b
    MULMOD
    // stack: y^2 % N, (x^3 + 3) % N, x, y, b
    EQ
    // stack: y^2 % N == (x^3 + 3) % N, x, y, b
    SWAP2
    // stack: y, x, y^2 % N == (x^3 + 3) % N, b
    ISZERO
    // stack: y==0, x, y^2 % N == (x^3 + 3) % N, b
    SWAP1
    // stack: x, y==0, y^2 % N == (x^3 + 3) % N, b
    ISZERO
    // stack: x==0, y==0, y^2 % N == (x^3 + 3) % N, b
    AND
    // stack: (x,y)==(0,0), y^2 % N == (x^3 + 3) % N, b
    SWAP2
    // stack: b, y^2 % N == (x^3 + 3) % N, (x,y)==(0,0)
    AND
    // stack: y^2 % N == (x^3 + 3) % N & (x < N) & (y < N), (x,y)==(0,0)
    OR
    // stack: y^2 % N == (x^3 + 3) % N & (x < N) & (y < N) || (x,y)==(0,0)
%endmacro

%macro ec_isidentity
    // stack: x, y
    ISZERO
    // stack: x==0, y
    SWAP1
    // stack: y, x==0
    ISZERO
    // stack: y==0, x==0
    AND
    // stack: y==0 & x==0
%endmacro

%macro ec_invalid_input
    // stack: retdest
    PUSH 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // stack: u256::MAX, retdest
    PUSH 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // stack: u256::MAX, u256::MAX, retdest
    SWAP2
    // stack: retdest, u256::MAX, u256::MAX
    JUMP
%endmacro