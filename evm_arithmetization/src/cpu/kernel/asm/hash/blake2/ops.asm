// 64-bit right rotation
%macro rotr_64(rot)
    // stack: value
    DUP1
    // stack: value, value
    PUSH $rot
    // stack: rot, value, value
    SHR
    // stack: value >> rot, value
    SWAP1
    PUSH $rot
    // stack: rot, value, value >> rot
    PUSH 64
    SUB
    // stack: 64 - rot, value, value >> rot
    SHL
    // stack: value << (64 - rot), value >> rot
    %as_u64
    // stack: (value << (64 - rot)) % (1 << 64), value >> rot
    ADD
%endmacro
