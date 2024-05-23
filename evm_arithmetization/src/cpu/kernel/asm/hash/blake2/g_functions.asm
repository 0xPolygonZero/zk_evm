%macro blake2_g_function(a, b, c, d)
    // Function to mix two input words, x and y, into the four words indexed by a, b, c, d (which
    // are in the range 0..16) in the internal state.
    // The internal state is stored in memory starting at the address start.
    // stack: x, y, start

    // Precompute final addresses
    PUSH $d DUP4 ADD
    PUSH $c DUP5 ADD
    PUSH $b DUP6 ADD
    PUSH $a DUP7 ADD

    // stack: addr_a, addr_b, addr_c, addr_d, x, y, start
    PUSH $a
    PUSH $c
    PUSH $b
    PUSH $d
    // stack: d, b, c, a, addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP11
    // stack: start, d, b, c, a, addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    MLOAD_GENERAL
    // stack: v[d], b, c, a, addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP1
    // stack: b, v[d], c, a, addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP11
    // stack: start, b, v[d], c, d, addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    MLOAD_GENERAL
    // stack: v[b], v[d], c, a, addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP2
    // stack: c, v[d], v[b], a, addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP11
    // stack: start, c, v[d], v[b], a, addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    MLOAD_GENERAL
    // stack: v[c], v[d], v[b], a, addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP3
    // stack: a, v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP11
    // stack: start, a, v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    MLOAD_GENERAL
    // stack: v[a], v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP3
    // stack: v[b], v[a], v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP10
    // stack: x, v[b], v[a], v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    ADD
    %as_u64
    // stack: v[a]' = (v[a] + v[b] + x) % 2^64, v[d], v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    %stack (a, d, b, c) -> (a, d, a, b, c)
    // stack: v[a]', v[d], v[a]', v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    XOR
    %rotr_64(32)
    // stack: v[d]' = (v[d] ^ v[a]') >>> 32, v[a]', v[b], v[c], addr_a, addr_b, addr_c, addr_d, x, y, start
    %stack (d, a, b, c) -> (c, d, a, b, d)
    // stack: v[c], v[d]', v[a]', v[b], v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    %as_u64
    // stack: v[c]' = (v[c] + v[d]') % 2^64, v[a]', v[b], v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    %stack (c, a, b, d) -> (b, c, a, c, d)
    // stack: v[b], v[c]', v[a]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    XOR
    %rotr_64(24)
    // stack: v[b]' = (v[b] ^ v[c]') >>> 24, v[a]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP1
    // stack: v[a]', v[b]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP2
    // stack: v[b]', v[a]', v[b]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP11
    // stack: y, v[b]', v[a]', v[b]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    ADD
    %as_u64
    // stack: v[a]'' = (v[a]' + v[b]' + y) % 2^64, v[b]', v[c]', v[d]', addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP3
    // stack: v[d]', v[b]', v[c]', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP4
    // stack: v[a]'', v[d]', v[b]', v[c]', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    XOR
    %rotr_64(16)
    // stack: v[d]'' = (v[a]'' ^ v[d]') >>> 16, v[b]', v[c]', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP2
    // stack: v[c]', v[b]', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP3
    // stack: v[d]'', v[c]', v[b]', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    ADD
    %as_u64
    // stack: v[c]'' = (v[c]' + v[d]'') % 2^64, v[b]', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    DUP1
    // stack: v[c]'', v[c]'', v[b]', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    SWAP2
    // stack: v[b]', v[c]'', v[c]'', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start
    XOR
    %rotr_64(63)
    // stack: v[b]'' = (v[b]' ^ v[c]'') >>> 63, v[c]'', v[d]'', v[a]'', addr_a, addr_b, addr_c, addr_d, x, y, start

    // Store resulting values at precomputed addresses
    %stack (vb, vc, vd, va, a, b, c, d, x, y, start) -> (va, a, vb, b, vc, c, vd, d)
    %rep 4
        MSTORE_GENERAL
    %endrep
%endmacro

%macro call_blake2_g_function(a, b, c, d, x_idx, y_idx)
    // stack: round, start
    DUP2
    %blake2_message_addr
    DUP1
    // stack: message_addr, message_addr, start, round, start
    PUSH $y_idx
    DUP5
    // stack: round, y_idx, message_addr, message_addr, start, round, start
    %blake2_permutation
    // stack: s[y_idx], message_addr, message_addr, start, round, start
    ADD
    MLOAD_GENERAL
    // stack: m[s[y_idx]], message_addr, start, round, start
    SWAP1
    // stack: message_addr, m[s[y_idx]], start, round, start
    PUSH $x_idx
    DUP5
    // stack: round, x_idx, message_addr, m[s[y_idx]], start, round, start
    %blake2_permutation
    // stack: s[x_idx], message_addr, m[s[y_idx]], start, round, start
    ADD
    MLOAD_GENERAL
    // stack: m[s[x_idx]], m[s[y_idx]], start, round, start
    %blake2_g_function($a, $b, $c, $d)
    // stack: round, start
%endmacro

global run_rounds_g_function:
    // stack: current_round, start, rounds, retdest
    DUP3
    // stack: rounds, current_round, start, rounds, retdest
    DUP2
    // stack: current_round, rounds, current_round, start, rounds, retdest
    EQ
    %jumpi(run_rounds_g_function_end)
    // stack: current_round, start, rounds, retdest
    %call_blake2_g_function(0, 4, 8, 12, 0, 1)
    %call_blake2_g_function(1, 5, 9, 13, 2, 3)
    %call_blake2_g_function(2, 6, 10, 14, 4, 5)
    %call_blake2_g_function(3, 7, 11, 15, 6, 7)
    %call_blake2_g_function(0, 5, 10, 15, 8, 9)
    %call_blake2_g_function(1, 6, 11, 12, 10, 11)
    %call_blake2_g_function(2, 7, 8, 13, 12, 13)
    %call_blake2_g_function(3, 4, 9, 14, 14, 15)
    // stack: current_round, start, rounds, retdest
    %increment
    // stack: current_round + 1, start, rounds, retdest
    %jump(run_rounds_g_function)
run_rounds_g_function_end:
    // stack: current_round, start, rounds, retdest
    %pop3
    // stack: retdest
    JUMP
