// Set @SEGMENT_JUMPDEST_BITS to one between positions [init_pos, final_pos],
// for the given context's code.
// Pre stack: init_pos, ctx, final_pos, retdest
// Post stack: (empty)
global verify_path_and_write_jumpdest_table:
    SWAP2
    DUP2
    ADD // final_addr
    // stack: final_addr, ctx, i, retdest
    SWAP2
    ADD // init_addr
loop:
    // stack: i, final_pos, retdest
    DUP2 DUP2 EQ // i == final_pos
    %jumpi(proof_ok)
    DUP2 DUP2 GT // i > final_pos
    %jumpi(proof_not_ok)

    // stack: i, final_pos, retdest
    DUP1
    MLOAD_GENERAL // SEGMENT_CODE == 0
    // stack: opcode, i, final_pos, retdest

    DUP1
    // Slightly more efficient than `%eq_const(0x5b) ISZERO`
    PUSH 0x5b
    SUB
    // stack: opcode != JUMPDEST, opcode, i, final_pos, retdest
    %jumpi(continue)

    // stack: JUMPDEST, i, code_len, retdest
    %stack (JUMPDEST, i) -> (@SEGMENT_JUMPDEST_BITS, i, JUMPDEST, i)
    ADD // address to write jumpdest bit, i already contains the context
    PUSH 1
    // stack: 1, addr, JUMPDEST, i
    MSTORE_GENERAL

continue:
    // stack: opcode, i, final_pos, retdest
    %add_const(code_bytes_to_skip)
    %mload_kernel_code
    // stack: bytes_to_skip, i, final_pos, retdest
    ADD
    // stack: i, final_pos, retdest
    %jump(loop)

proof_ok:
    // stack: i, final_pos, retdest
    // We already know final_pos is a jumpdest
    %stack (i, final_pos) -> (@SEGMENT_JUMPDEST_BITS, final_pos)
    ADD // final_pos already contains the context
    PUSH 1
    MSTORE_GENERAL
    JUMP
proof_not_ok:
    %pop2
    JUMP

// Determines how many bytes away is the next opcode, based on the opcode we read.
// If we read a PUSH<n> opcode, next opcode is in n + 1 bytes, otherwise it's the next one.
//
// Note that the range of PUSH opcodes is [0x60, 0x80). I.e. PUSH1 is 0x60
// and PUSH32 is 0x7f.
code_bytes_to_skip:
    %rep 96
        BYTES 1 // 0x00-0x5f
    %endrep

    BYTES 2
    BYTES 3
    BYTES 4
    BYTES 5
    BYTES 6
    BYTES 7
    BYTES 8
    BYTES 9
    BYTES 10
    BYTES 11
    BYTES 12
    BYTES 13
    BYTES 14
    BYTES 15
    BYTES 16
    BYTES 17
    BYTES 18
    BYTES 19
    BYTES 20
    BYTES 21
    BYTES 22
    BYTES 23
    BYTES 24
    BYTES 25
    BYTES 26
    BYTES 27
    BYTES 28
    BYTES 29
    BYTES 30
    BYTES 31
    BYTES 32
    BYTES 33

    %rep 128
        BYTES 1 // 0x80-0xff
    %endrep


// A proof attesting that jumpdest is a valid jump destination is
// either 0 or an index 0 < i <= jumpdest - 32.
// A proof is valid if:
// - i == 0 and we can go from the first opcode to jumpdest and code[jumpdest] = 0x5b
// - i > 0 and:
//     a) for j in {i+0,..., i+31} code[j] != PUSHk for all k >= 32 - j - i,
//     b) we can go from opcode i+32 to jumpdest,
//     c) code[jumpdest] = 0x5b.
// To reduce the number of instructions, when i > 32 we load all the bytes code[j], ...,
// code[j + 31] in a single 32-byte word, and check a) directly on the packed bytes.
// We perform the "packed verification" by checking, for every byte, that it's not part
// of the forbidden opcodes. For byte n in {1, 32}, this means:
//     - The first three bits are the PUSH prefix 011.
//     - The five last bits are > 32 - n.
// stack: proof_prefix_addr, jumpdest, ctx, retdest
// stack: (empty)
global write_table_if_jumpdest:
    // stack: proof_prefix_addr, jumpdest, ctx, retdest
    %stack
        (proof_prefix_addr, jumpdest, ctx) ->
        (ctx, jumpdest, jumpdest, ctx, proof_prefix_addr)
    ADD // combine context and offset to make an address (SEGMENT_CODE == 0)
    MLOAD_GENERAL
    // stack: opcode, jumpdest, ctx, proof_prefix_addr, retdest

    %jump_neq_const(0x5b, return)

    // stack: jumpdest, ctx, proof_prefix_addr, retdest
    SWAP2 DUP1
    // stack: proof_prefix_addr, proof_prefix_addr, ctx, jumpdest
    ISZERO
    %jumpi(verify_path_and_write_jumpdest_table)


    // stack: proof_prefix_addr, ctx, jumpdest, retdest
    // If we are here we need to check that the next 32 bytes are not
    // PUSHXX for XX > 32 - n, n in {1, 32}.

    %stack
        (proof_prefix_addr, ctx) ->
        (ctx, proof_prefix_addr, 32, proof_prefix_addr, ctx)
    ADD // combine context and offset to make an address (SEGMENT_CODE == 0)
    MLOAD_32BYTES
    // packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    DUP1 %shl_const(1)
    DUP2 %shl_const(2)
    AND
    // stack: (is_1_at_pos_2_and_3|(X)⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    // X denotes any value in {0,1} and Z^i is Z repeated i times
    DUP2
    NOT
    AND
    // stack: (is_0_at_pos_1_and_is_1_at_pos_2_and_3|(X)⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    // stack: (is_push|X⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    PUSH 0x8080808080808080808080808080808080808080808080808080808080808080
    // stack: mask, (is_push|X⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    DUP3
    %and_const(0x1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F)
    // stack: (000|X⁵)³², mask, (is_push|X⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    // For opcode PUSHXX, the right-most 5 bits contain XX - 1.
    // Ignoring the first 3 bits of prefix, the first opcode must NOT be PUSH32, the second opcode
    // must NOT be PUSH31 or PUSH32 [...], the 32-th opcode must NOT be a PUSH.
    // We can check it by adding the trimmed opcodes with a certain value such that the addition overflows iff
    // the five bits of an opcode are forbidden:
    //     000xxxxx|000xxxxx|...|000xxxxx|000xxxxx
    //   + 00000001|00000010|...|00011111|00100000
    // For e.g. the first opcode, the addition will overflow iff xxxxx = 0b11111 = 0d31.
    // For the last opcode, since any PUSHXX operation is forbidden, the overflow bit is set manually.
    // Note that since the result of a five-bit addition will always use at most six bits, the overflow bit will always be
    // bit number 3, and all opcodes are checked in parallel without overflowing into each other.
    %add_const(0x0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20)
    %shl_const(2)
    // stack: (is_overflow|(X)⁷)³², mask, (is_push|X⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    DUP2
    AND
    // stack: (is_overflow|0⁷)³², mask, (is_push|X⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    SWAP2
    AND
    // stack: (is_push|0⁷)³², (is_overflow|0⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest
    AND
    // stack: (is_forbidden_opcode|0⁷)³², packed_opcodes, proof_prefix_addr, ctx, jumpdest, retdest

    // If we received a proof it MUST be valid or we abort immediately. This
    // is especially important for non-jumpdest proofs. Otherwise a malicious
    // prover might mark a valid jumpdest as invalid by providing an invalid proof
    // that makes verify_non_jumpdest return prematurely.
    %jumpi(panic)
    POP
    %add_const(32)

    // check the remaining path
    %jump(verify_path_and_write_jumpdest_table)

return:
    // stack: proof_prefix_addr, ctx, jumpdest, retdest
    // or
    // stack: jumpdest, ctx, proof_prefix_addr, retdest
    %pop3
    JUMP

%macro write_table_if_jumpdest
    %stack (proof_prefix_addr, jumpdest, ctx) -> (proof_prefix_addr, jumpdest, ctx, %%after)
    %jump(write_table_if_jumpdest)
%%after:
%endmacro

// Write the jumpdest table. This is done by
// non-deterministically guessing the sequence of jumpdest
// addresses used during program execution within the current context.
// For each jumpdest address we also non-deterministically guess
// a proof, which is another address in the code such that
// is_jumpdest doesn't abort, when the proof is at the top of the stack
// an the jumpdest address below. If that's the case we set the
// corresponding bit in @SEGMENT_JUMPDEST_BITS to 1.
//
// stack: ctx, code_len, retdest
// stack: (empty)
global jumpdest_analysis:
    // If address > 0 then address is interpreted as address' + 1
    // and the next prover input should contain a proof for address'.
    PROVER_INPUT(jumpdest_table::next_address)
    DUP1 %jumpi(check_proof)
    // If address == 0 there are no more jump destinations to check
    POP
// This is just a hook used for avoiding verification of the jumpdest
// table in another context. It is useful during proof generation,
// allowing the avoidance of table verification when simulating user code.
global jumpdest_analysis_end:
    %pop2
    JUMP
check_proof:
    // stack: address, ctx, code_len, retdest
    DUP3 DUP2 %assert_le
    %decrement
    // stack: address, ctx, code_len, retdest
    DUP2 SWAP1
    // stack: address, ctx, ctx, code_len, retdest
    // We read the proof
    PROVER_INPUT(jumpdest_table::next_proof)
    // stack: proof, address, ctx, ctx, code_len, retdest
    %write_table_if_jumpdest
    // stack: ctx, code_len, retdest

    %jump(jumpdest_analysis)

%macro jumpdest_analysis
    %stack (ctx, code_len) -> (ctx, code_len, %%after)
    %jump(jumpdest_analysis)
%%after:
%endmacro

// Non-deterministically find the closest opcode to addr
// and call write_table_if_jumpdest so that `@SEGMENT_JUMPDEST_BITS`
// will contain a 0 if and only if addr is not a jumpdest
// stack: addr, retdest
// stack: (empty)
global verify_non_jumpdest:
    // stack: addr, retdest
    GET_CONTEXT
    SWAP1
    // stack: addr, ctx
    PROVER_INPUT(jumpdest_table::non_jumpdest_proof)
    // stack: proof, addr, ctx,
    // Check that proof <= addr as otherwise it allows
    // a malicious prover to leave `@SEGMENT_JUMPDEST_BITS` as 0
    // at position addr while it shouldn't.
    DUP2 DUP2
    %assert_le
    %write_table_if_jumpdest
    JUMP

%macro verify_non_jumpdest
    %stack (addr) -> (addr, %%after)
    %jump(verify_non_jumpdest)
%%after:
%endmacro
