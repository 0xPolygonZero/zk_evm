// Get the number of bytes required to represent the given scalar.
// Note that we define num_bytes(0) to be 1.
global num_bytes:
    // stack: x, retdest
    DUP1 ISZERO %jumpi(return_1)
    // stack: x, retdest
    %num_bits
    // stack: num_bits, retdest
    // convert number of bits to number of bytes
    %add_const(7)
    %shr_const(3)

    SWAP1
    JUMP

return_1:
    // stack: x, retdest
    %stack(x, retdest) -> (retdest, 1)
    JUMP

// Convenience macro to call num_bytes and return where we left off.
%macro num_bytes
    %stack (x) -> (x, %%after)
    %jump(num_bytes)
%%after:
%endmacro

%macro num_bits
    // Non-deterministically guess the number of bits
    // stack: x
    PROVER_INPUT(num_bits)
    %stack (num_bits, x) -> (num_bits, x, num_bits)
    %decrement
    SHR
    // stack: 1, num_bits
    %assert_eq_const(1)
    // stack: num_bits
%endmacro
