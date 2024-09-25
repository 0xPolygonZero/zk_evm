global ret_zero_ec_mul:
    // stack: x, y, s, retdest
    %pop3
    // stack: retdest
    PUSH 0
    // stack: 0, retdest
    PUSH 0
    // stack: 0, 0, retdest
    SWAP2
    // stack: retdest, 0, 0
    JUMP

global ret_zero_ec_twisted_mul:
    // stack: X: 2, Y: 2, s, retdest
    %stack (garbage: 5, retdest) -> (retdest, 0, 0, 0, 0)
    JUMP

global ec_double_retself:
    %stack (x, y, retdest) -> (retdest, x, y)
    JUMP

global ec_twisted_double_retself:
    %stack (X: 2, Y: 2, retdest) -> (retdest, X, Y)
    JUMP

// Check if (x,y)==(0,0)
%macro ec_isidentity
    // stack: x, y
    OR
    // stack: x | y
    ISZERO
    // stack: (x,y) == (0,0)
%endmacro

