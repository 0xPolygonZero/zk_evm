global checkpoint:
    // stack: (empty)
    PUSH 1
    POP
global before_push_1:
    PUSH 1
    POP
    %current_checkpoint
global debug_shalom_netangui:
    // stack: current_checkpoint
    DUP1
    PUSH @SEGMENT_JOURNAL_CHECKPOINTS
    %build_kernel_address
    %journal_size
    // stack: journal_size, addr, current_checkpoint
    MSTORE_GENERAL
    // stack: current_checkpoint
    %mload_context_metadata(@CTX_METADATA_CHECKPOINTS_LEN)
    // stack: i, current_checkpoint
    DUP2 DUP2 %mstore_current(@SEGMENT_CONTEXT_CHECKPOINTS)
    // stack: i, current_checkpoint
    %increment
    %mstore_context_metadata(@CTX_METADATA_CHECKPOINTS_LEN)
    // stack: current_checkpoint
    %increment
    %mstore_global_metadata(@GLOBAL_METADATA_CURRENT_CHECKPOINT)
    // stack: (empty)
global debug_cp_bef_jmp:
    JUMP