// "T_1" in the SHA-256 spec
%macro sha2_temp_word1
    // stack: e, f, g, e, h, K[i], W[i]
    %sha2_choice
    // stack: Ch(e, f, g), e, h, K[i], W[i]
    SWAP1
    // stack: e, Ch(e, f, g), h, K[i], W[i]
    %sha2_bigsigma_1
    // stack: Sigma_1(e), Ch(e, f, g), h, K[i], W[i]
    ADD
    ADD
    ADD
    ADD
    // stack: Ch(e, f, g) + Sigma_1(e) + h + K[i] + W[i]
%endmacro

// "T_2" in the SHA-256 spec
%macro sha2_temp_word2
    // stack: a, b, c
    DUP1
    // stack: a, a, b, c
    %sha2_bigsigma_0
    // stack: Sigma_0(a), a, b, c
    SWAP3
    // stack: c, a, b, Sigma_0(a)
    %sha2_majority
    // stack: Maj(c, a, b), Sigma_0(a)
    ADD
    // stack: Maj(c, a, b) + Sigma_0(a)
%endmacro
