// 32-bit right rotation
%macro rotr(rot)
    // stack: value
    PUSH $rot
    // stack: rot, value
    DUP2
    DUP2
    // stack: rot, value, rot, value
    SHR
    // stack: value >> rot, rot, value
    %stack (shifted, rot, value) -> (rot, value, shifted)
    // stack: rot, value, value >> rot
    PUSH 32
    SUB
    // stack: 32 - rot, value, value >> rot
    SHL
    // stack: value << (32 - rot), value >> rot
    %as_u32
    // stack: (value << (32 - rot)) % (1 << 32), value >> rot
    ADD
%endmacro

%macro sha2_sigma_0
    // stack: x
    DUP1
    // stack: x, x
    %rotr(7)
    // stack: rotr(x, 7), x
    SWAP1
    // stack: x, rotr(x, 7)
    DUP1
    // stack: x, x, rotr(x, 7)
    %rotr(18)
    // stack: rotr(x, 18), x, rotr(x, 7)
    SWAP1
    // stack: x, rotr(x, 18), rotr(x, 7)
    %shr_const(3)
    // stack: shr(x, 3), rotr(x, 18), rotr(x, 7)
    XOR
    XOR
%endmacro

%macro sha2_sigma_1
    // stack: x
    DUP1
    // stack: x, x
    %rotr(17)
    // stack: rotr(x, 17), x
    SWAP1
    // stack: x, rotr(x, 17)
    DUP1
    // stack: x, x, rotr(x, 17)
    %rotr(19)
    // stack: rotr(x, 19), x, rotr(x, 17)
    SWAP1
    // stack: x, rotr(x, 19), rotr(x, 17)
    PUSH 10
    SHR
    // stack: shr(x, 10), rotr(x, 19), rotr(x, 17)
    XOR
    XOR
%endmacro

%macro sha2_bigsigma_0
    // stack: x
    DUP1
    // stack: x, x
    %rotr(2)
    // stack: rotr(x, 2), x
    SWAP1
    // stack: x, rotr(x, 2)
    DUP1
    // stack: x, x, rotr(x, 2)
    %rotr(13)
    // stack: rotr(x, 13), x, rotr(x, 2)
    SWAP1
    // stack: x, rotr(x, 13), rotr(x, 2)
    %rotr(22)
    // stack: rotr(x, 22), rotr(x, 13), rotr(x, 2)
    XOR
    XOR
%endmacro

%macro sha2_bigsigma_1
    // stack: x
    DUP1
    // stack: x, x
    %rotr(6)
    // stack: rotr(x, 6), x
    SWAP1
    // stack: x, rotr(x, 6)
    DUP1
    // stack: x, x, rotr(x, 6)
    %rotr(11)
    // stack: rotr(x, 11), x, rotr(x, 6)
    SWAP1
    // stack: x, rotr(x, 11), rotr(x, 6)
    %rotr(25)
    // stack: rotr(x, 25), rotr(x, 11), rotr(x, 6)
    XOR
    XOR
%endmacro

%macro sha2_choice
    // stack: x, y, z
    SWAP1
    // stack: y, x, z
    DUP3
    // stack: z, y, x, z
    XOR
    // stack: z xor y, x, z
    AND
    // stack: (z xor y) and x, z
    XOR
    // stack: ((z xor y) and x) xor z == (x and y) xor (not x and z)
%endmacro

%macro sha2_majority
    // stack: x, y, z
    DUP2
    DUP2
    AND
    // stack: x and y, x, y, z
    SWAP2
    // stack: y, x, x and y, z
    OR
    // stack: y or x, x and y, z
    %stack(y_or_x, x_and_y, z) -> (z, y_or_x, x_and_y)
    AND
    // stack: (z and (y or x), x and y
    OR
    // stack: (z and (y or x) or (x and y) == (x and y) or (x and z) or (y and z)
%endmacro
