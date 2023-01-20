/// def tate(P: Curve, Q: TwistedCurve) -> Fp12:
///     out = miller_loop(P, Q)
///
///     inv = inv_fp12(out)
///     out = frob_fp12(6, out)
///     out = mul_fp12(out, inv)
///
///     acc = frob_fp12(2, out)
///     out = mul_fp12(out, acc)
///
///     pow = power(out)
///     out = frob_fp12(3, out) 
///     out = mul_fp12(out, pow)
///
///     return out

global tate:
    // stack:                        ptr, out, retdest
    DUP2
    // stack:                   out, ptr, out, retdest
    PUSH post_miller
    // stack:      post_miller, out, ptr, out, retdest
    SWAP2
    // stack:      ptr, out, post_miller, out, retdest
    %jump(miller_init)
global post_miller:    
    // stack:                             out, retdest
    PUSH tate_mul_1
    // stack:                 tate_mul_1, out, retdest
    PUSH 100 
    // stack:            100, tate_mul_1, out, retdest
    DUP3 
    // stack:       out, 100, tate_mul_1, out, retdest
    %jump(inv_fp12)
tate_mul_1:
    // stack:                             out, retdest  {100: inv}
    %frob_fp12_6
    // stack:                             out, retdest  {100: inv}
    PUSH tate_mul_2
    // stack:                 tate_mul_2, out, retdest  {100: inv}
    DUP2
    // stack:            out, tate_mul_2, out, retdest  {100: inv}
    PUSH 100 
    // stack:       100, out, tate_mul_2, out, retdest  {100: inv}
    DUP2
    // stack:  out, 100, out, tate_mul_2, out, retdest  {100: inv}
    %jump(mul_fp12)
tate_mul_2:
    // stack:                             out, retdest  {100: inv}
    PUSH tate_power
    // stack:                 tate_power, out, retdest  {100: inv}
    DUP2
    // stack:            out, tate_power, out, retdest  {100: inv}
    PUSH 100
    // stack:       100, out, tate_power, out, retdest  {100: inv}       
    DUP2 
    // stack:  out, 100, out, tate_power, out, retdest  {100: inv}
    %frob_fp12_2_
    // stack:       100, out, tate_power, out, retdest  {100: acc} 
    DUP2
    // stack:  out, 100, out, tate_power, out, retdest  {100: acc}
    %jump(mul_fp12)
tate_power: 
    // stack:                             out, retdest  {100: acc}
    PUSH tate_return
    // stack:                tate_return, out, retdest  {100: acc}
    PUSH 100
    // stack:           100, tate_return, out, retdest  {100: acc}
    PUSH 300
    // stack:      300, 100, tate_return, out, retdest  {100: acc}
    DUP4
    // stack: out, 300, 100, tate_return, out, retdest  {100: acc}
    %move_fp12
    // stack:      300, 100, tate_return, out, retdest  {100: acc, 300: out}
    %jump(power)
tate_return: 
    // stack:                             out, retdest  {100: pow}
    PUSH 100
    // stack:                        100, out, retdest  {100: pow}
    DUP2
    // stack:                   out, 100, out, retdest  {100: pow}
    %frob_fp12_3
    // stack:                   out, 100, out, retdest  {100: pow}
    %jump(mul_fp12)
