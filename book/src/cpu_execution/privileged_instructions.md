## Privileged instructions

To ease and speed-up proving time, the zkEVM supports custom, privileged
instructions that can only be executed by the kernel. Any appearance of
those privileged instructions in a contract bytecode for instance would
result in an unprovable state.

In what follows, we denote by $p_{BN}$ the characteristic of the BN254
curve base field, curve for which Ethereum supports the ecAdd, ecMul and
ecPairing precompiles.

1.  `ADDFP254`. Pops 2 elements from the stack interpreted as BN254 base
    field elements, and pushes their addition modulo $p_{BN}$ onto the
    stack.

2.  `MULFP254`. Pops 2 elements from the stack interpreted as BN254 base
    field elements, and pushes their product modulo $p_{BN}$ onto the
    stack.

3.  `SUBFP254`. Pops 2 elements from the stack interpreted as BN254 base
    field elements, and pushes their difference modulo $p_{BN}$ onto the
    stack. This instruction behaves similarly to the SUB (0x03) opcode,
    in that we subtract the second element of the stack from the initial
    (top) one.

4.  `SUBMOD`. Pops 3 elements from the stack, and pushes the modular
    difference of the first two elements of the stack by the third one.
    It is similar to the SUB instruction, with an extra pop for the
    custom modulus.

5.  `KECCAK_GENERAL`. Pops 2 elements (a Memory address, followed by a
    length $\ell$) and pushes the hash of the memory portion starting at
    the constructed address and of length $\ell$. It is similar to
    KECCAK256 (0x20) instruction, but can be applied to any memory
    section (i.e. even privileged ones).

6.  `MSTORE_32BYTES`. Pops 2 elements from the stack (a Memory address,
    and then a value), and pushes a new address' onto the stack. The
    value is being decomposed into bytes and written to memory, starting
    from the fetched address. The new address being pushed is computed
    as the initial address + the length of the byte sequence being
    written to memory. Note that similarly to PUSH (0x60-0x7F)
    instructions, there are 32 MSTORE_32BYTES instructions, each
    corresponding to a target byte length (length 0 is ignored, for the
    same reasons as MLOAD_32BYTES, see below). Writing to memory an
    integer fitting in $n$ bytes with a length $\ell < n$ will result in
    the integer being truncated. On the other hand, specifying a length
    $\ell$ greater than the byte size of the value being written will
    result in padding with zeroes. This process is heavily used when
    resetting memory sections (by calling MSTORE_32BYTES_32 with the
    value 0).

7. `INCR`. Reads the `N`th element of the stack, and increments it in-place
    by one without pushing or popping. There are 4 INCR operations, namely
    INCR1, INCR2, INCR3, INCR4 to increment respectively the 1st, 2nd, 3rd
    and 4th stack elements.

8.  `PROVER_INPUT`. Pushes a single prover input onto the stack.

9.  `GET_CONTEXT`. Pushes the current context onto the stack. The kernel
    always has context 0.

10.  `SET_CONTEXT`. Pops the top element of the stack and updates the
    current context to this value. It is usually used when calling
    another contract or precompile, to distinguish the caller from the
    callee.

11. `MLOAD_32BYTES`. Pops 2 elements from the stack (a Memory address,
    and then a length $\ell$), and pushes a value onto the stack. The
    pushed value corresponds to the U256 integer read from the
    big-endian sequence of length $\ell$ from the memory address being
    fetched. Note that an empty length is not valid, nor is a length
    greater than 32 (as a U256 consists in at most 32 bytes). Missing
    these conditions will result in an unverifiable proof.

12. `EXIT_KERNEL`. Pops 1 element from the stack. This instruction is
    used at the end of a syscall, before proceeding to the rest of the
    execution logic. The popped element, *kexit_info*, contains several
    pieces of information like the current program counter, the current
    amount of gas used, and whether we are in kernel (i.e. privileged)
    mode or not.

13. `MLOAD_GENERAL`. Pops 1 elements (a Memory address), and pushes the
    value stored at this memory address onto the stack. It can read any
    memory location, general (similarly to MLOAD (0x51) instruction) or
    privileged.

14. `MSTORE_GENERAL`. Pops 2 elements (a value and a Memory address),
    and writes the popped value from the stack at the fetched address.
    It can write to any memory location, general (similarly to MSTORE
    (0x52) / MSTORE8 (0x53) instructions) or privileged.
