// Implementation of the BN254 twist endomorphism.

/// Frobenius map over BN254 quadratic extension.
%macro frob_fp254_2
    // stack: X = (x, x_)
    %conj_fp254_2
    // stack: frob(X)
%endmacro

%macro bn_endomorphism
    // stack: X: 2, Y: 2
    %frob_fp254_2
    // stack: X', Y
    %swap_fp254_2
    // stack: Y, X'
    %frob_fp254_2
    // stack: Y', X'
    PUSH @BN_ENDO_Y_COORD_IM
    PUSH @BN_ENDO_Y_COORD_RE
    %mul_fp254_2
    // stack: φ_y.Y', X'
    %swap_fp254_2
    // stack: X', φ_y.Y'
    PUSH @BN_ENDO_X_COORD_IM
    PUSH @BN_ENDO_X_COORD_RE
    %mul_fp254_2
    // stack: φ_x.X', φ_y.Y'
%endmacro
