/// def bn254_pairing(pairs: List((Curve, TwistedCurve))) -> Fp12:
///     
///     for P, Q in pairs:
///         if not (P.is_valid and Q.is_valid):
///             return @U256_MAX
///     
///     out = 1
///     for P, Q in pairs:
///         out *= miller_loop(P, Q)
///
///     return bn254_final_exponent(out)

global bn254_pairing:
    // stack: k, inp, out, retdest
    DUP1

bn254_input_check:
    // stack:       j    , k, inp 
    DUP1
    ISZERO
    // stack: end?, j    , k, inp
    %jumpi(bn254_pairing_start)
    // stack:       j    , k, inp
    %sub_const(1)
    // stack:       j=j-1, k, inp

    %stack (j, k, inp) -> (j, inp, j, k, inp)
    // stack:        j, inp, j, k, inp
    %mul_const(6)
    ADD
    // stack:  inp_j=inp+6j, j, k, inp
    DUP1
    // stack:  inp_j, inp_j, j, k, inp
    %load_fp254_2
    // stack:    P_j, inp_j, j, k, inp
    %bn_check
    // stack: valid?, inp_j, j, k, inp
    ISZERO
    %jumpi(bn_pairing_invalid_input)
    // stack:         inp_j, j, k, inp
    DUP1
    // stack: inp_j , inp_j, j, k, inp
    %add_const(2)
    // stack: inp_j', inp_j, j, k, inp
    %load_fp254_4
    // stack:    Q_j, inp_j, j, k, inp
    %bn_check_twisted
    // stack: valid?, inp_j, j, k, inp
    ISZERO
    %jumpi(bn_pairing_invalid_input)
    // stack:         inp_j, j, k, inp
    POP
    %jump(bn254_input_check)

bn_pairing_invalid_input:
    // stack:  inp_j, j, k, inp, out, retdest
    %stack (inp_j, j, k, inp, out, retdest) -> (retdest, @U256_MAX)
    JUMP

bn254_pairing_start:
    // stack:      0, k, inp, out, retdest
    %stack (j, k, inp, out) -> (out, 1, k, inp, out)
    // stack: out, 1, k, inp, out, retdest
    %mstore_kernel_bn254_pairing
    // stack:         k, inp, out, retdest

bn254_pairing_loop:
    // stack:       k, inp, out, retdest
    DUP1
    ISZERO
    // stack: end?, k, inp, out, retdest
    %jumpi(bn254_final_exponent)
    // stack:       k, inp, out, retdest
    %sub_const(1)
    // stack:   k=k-1, inp, out, retdest

    %stack (k, inp, out) -> (k, inp, 0, mul_fp254_12, 0, out, out, bn254_pairing_loop, k, inp, out)
    // stack: k, inp, 0, mul_fp254_12, 0, out, out, bn254_pairing_loop, k, inp, out retdest
    %mul_const(6)
    ADD
    // stack:  inp_k, 0, mul_fp254_12, 0, out, out, bn254_pairing_loop, k, inp, out retdest
    %jump(bn254_miller)
