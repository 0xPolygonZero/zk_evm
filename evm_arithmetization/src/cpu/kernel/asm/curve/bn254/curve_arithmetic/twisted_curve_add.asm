// Elliptic curve addition on the twist of BN254 curve.
// Assumption: (X0,Y0) is a valid point.
// Uses the standard affine addition formula.
global bn_twisted_add:
    // stack: X0: 2, Y0: 2, X1: 2, Y1: 2, retdest

    // Check if the first point is the identity.
    %dup_fp254_2_2
    // stack: Y0, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_2
    // stack: X0, Y0, X0, Y0, X1, Y1, retdest
    %bn_check_twisted_ident
    // stack: (X0,Y0)==(0,0), X0, Y0, X1, Y1, retdest
    %jumpi(bn_twisted_add_fst_zero)
    // stack: X0, Y0, X1, Y1, retdest

    // Check if the second point is the identity.
    %dup_fp254_2_6
    // stack: Y1, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_6
    // stack: X1, Y1, X0, Y0, X1, Y1, retdest
    %bn_check_twisted_ident
    // stack: (X1,Y1)==(0,0), X0, Y0, X1, Y1, retdest
    %jumpi(bn_twisted_add_snd_zero)
    // stack: X0, Y0, X1, Y1, retdest

    // Check if both points have the same X-coordinate.
    %dup_fp254_2_4
    // stack: X1, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_2
    // stack: X0, X1, X0, Y0, X1, Y1, retdest
    %eq_fp254_2
    // stack: X0 == X1, X0, Y0, X1, Y1, retdest
    %jumpi(bn_twisted_add_equal_first_coord)
    // stack: X0, Y0, X1, Y1, retdest

    // Otherwise, we can use the standard formula.
    // Compute lambda = (Y0 - Y1)/(X0 - X1)
    %dup_fp254_2_6
    // stack: Y1, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_4
    // stack: Y0, Y1, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: Y0 - Y1, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_6
    // stack: X1, Y0 - Y1, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_4
    // stack: X0, X1, Y0 - Y1, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: X0 - X1, Y0 - Y1, X0, Y0, X1, Y1, retdest
    %divr_fp254_2
    // stack: lambda, X0, Y0, X1, Y1, retdest
    %jump(bn_twisted_add_valid_points_with_lambda)

// BN254 twisted elliptic curve addition.
// Assumption: (X0,Y0) == (0,0)
bn_twisted_add_fst_zero:
    // stack: X0: 2, Y0: 2, X1: 2, Y1: 2, retdest
    // Just return (X1, Y1)
    %stack (X0: 2, Y0: 2, X1: 2, Y1: 2, retdest) -> (retdest, X1, Y1)
    JUMP

// BN254 twisted elliptic curve addition.
// Assumption: (X1,Y1) == (0,0)
bn_twisted_add_snd_zero:
    // stack: X0: 2, Y0: 2, X1: 2, Y1: 2, retdest

    // Just return (X0,Y0)
    %stack (X0: 2, Y0: 2, X1: 2, Y1: 2, retdest) -> (retdest, X0, Y0)
    JUMP

// BN254 twisted elliptic curve addition.
// Assumption: lambda = (Y0 - Y1)/(X0 - X1)
bn_twisted_add_valid_points_with_lambda:
    // stack: lambda: 2, X0: 2, Y0: 2, X1: 2, Y1: 2, retdest

    // Compute X2 = lambda^2 - X1 - X0
    %dup_fp254_2_2
    // stack: X0, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_8
    // stack: X1, X0, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_4
    // stack: lambda, X1, X0, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_0
    // stack: lambda, lambda, X1, X0, lambda, X0, Y0, X1, Y1, retdest
    %mul_fp254_2
    // stack: lambda^2, X1, X0, lambda, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: lambda^2 - X1, X0, lambda, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: X2, lambda, X0, Y0, X1, Y1, retdest

    // Compute Y2 = lambda*(X1 - X2) - Y1
    %dup_fp254_2_0
    // stack: X2, X2, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_10
    // stack: X1, X2, X2, lambda, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: X1 - X2, X2, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_4
    // stack: lambda, X1 - X2, X2, lambda, X0, Y0, X1, Y1, retdest
    %mul_fp254_2
    // stack: lambda * (X1 - X2), X2, lambda, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_12
    // stack: Y1, lambda * (X1 - X2), X2, lambda, X0, Y0, X1, Y1, retdest
    %stack (Y1: 2, T: 2) -> (T, Y1)
    // stack: lambda * (X1 - X2), Y1, X2, lambda, X0, Y0, X1, Y1, retdest
    %sub_fp254_2
    // stack: Y2, X2, lambda, X0, Y0, X1, Y1, retdest

    // Return X2, Y2
    %stack (Y2: 2, X2: 2, lambda: 2, X0: 2, Y0: 2, X1: 2, Y1: 2, retdest) -> (retdest, X2, Y2)
    JUMP

// BN254 twisted elliptic curve addition.
// Assumption: (X0,Y0) and (X1,Y1) are valid points and X0 == X1
bn_twisted_add_equal_first_coord:
    // stack: X0, Y0, X1, Y1, retdest with X0 == X1

    // Check if the points are equal
    %dup_fp254_2_2
    // stack: Y0, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_8
    // stack: Y1, Y0, X0, Y0, X1, Y1, retdest
    %eq_fp254_2
    // stack: Y1 == Y0, X0, Y0, X1, Y1, retdest
    %jumpi(bn_twisted_add_equal_points)
    // stack: X0, Y0, X1, Y1, retdest

    // Otherwise, one is the negation of the other so we can return the identity.
    %stack (garbage: 8, retdest) -> (retdest, 0, 0, 0, 0)
    // stack: retdest, X=0, Y=0
    JUMP


// BN254 twisted elliptic curve addition.
// Assumption: X0 == X1 and Y0 == Y1
// Standard doubling formula.
bn_twisted_add_equal_points:
    // stack: X0, Y0, X1, Y1, retdest

    // Compute lambda = 3/2 * X0^2 / Y0
    %dup_fp254_2_0
    // stack: X0, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_0
    // stack: X0, X0, X0, Y0, X1, Y1, retdest
    %mul_fp254_2
    // stack: X0^2, X0, Y0, X1, Y1, retdest
    PUSH 0X183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea5 // 3/2 in the base field
    // stack: 3/2, X0^2, X0, Y0, X1, Y1, retdest
    %scale_fp254_2
    // stack: 3/2 * X0^2, X0, Y0, X1, Y1, retdest
    %dup_fp254_2_4
    // stack: Y0, 3/2 * X0^2, X0, Y0, X1, Y1, retdest
    %divr_fp254_2
    // stack: lambda, X0, Y0, X1, Y1, retdest
    %jump(bn_twisted_add_valid_points_with_lambda)

// BN254 twisted elliptic curve doubling.
// Assumption: (X0,Y0) is a valid point.
// Standard doubling formula.
global bn_twisted_double:
    // stack: X, Y, retdest
    %dup_bn_g2
    // stack: X, Y, X, Y, retdest
    %bn_check_twisted_ident
    // stack: (X,Y)==(0,0), X, Y, retdest
    %jumpi(ec_twisted_double_retself)
    %dup_bn_g2
    // stack: X, Y, X, Y, retdest
    %jump(bn_twisted_add_equal_points)

// Convenience macro to call bn_twisted_add and return where we left off.
%macro bn_twisted_add
    %stack (X0: 2, Y0: 2, X1: 2, Y1: 2) -> (X0, Y0, X1, Y1, %%after)
    %jump(bn_twisted_add)
%%after:
%endmacro

%macro bn_twisted_sub
    // stack: X0: 2, Y0: 2, X1: 2, Y1: 2
    %swap_fp254_2_4
    // stack: Y1, Y0, X1, X0
    PUSH 0 PUSH 0
    %sub_fp254_2
    // stack: -Y1, Y0, X1, X0
    %stack (Y1: 2, Y0: 2, X1: 2, X0: 2) -> (X0, Y0, X1, Y1, %%after)
    %jump(bn_twisted_add)
%%after:
%endmacro

// Convenience macro to call bn_twisted_double and return where we left off.
%macro bn_twisted_double
    %stack (X: 2, Y: 2) -> (X, Y, %%after)
    %jump(bn_twisted_double)
%%after:
%endmacro
