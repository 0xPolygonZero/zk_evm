global sys_gas:
    // stack: kexit_info
    %charge_gas_const(@GAS_BASE)
    // stack: kexit_info
    DUP1 %shr_const(192)
    // stack: gas_used, kexit_info
    %ctx_gas_limit
    // stack: gas_limit, gas_used, kexit_info
    SUB
    // stack: gas_remaining, kexit_info
    SWAP1
    EXIT_KERNEL

%macro ctx_gas_limit
    %mload_context_metadata(@CTX_METADATA_GAS_LIMIT)
%endmacro


%macro refund_gas
    // stack: amount
    DUP1 %journal_refund
    %mload_global_metadata(@GLOBAL_METADATA_REFUND_COUNTER)
    ADD
    %mstore_global_metadata(@GLOBAL_METADATA_REFUND_COUNTER)
%endmacro

// Charge gas. Faults if we exceed the limit for the current context.
%macro charge_gas
    // stack: gas, kexit_info
    %shl_const(192)
    ADD
    // stack: kexit_info'
    %ctx_gas_limit
    // stack: gas_limit, kexit_info'
    DUP2 %shr_const(192)
    // stack: gas_used, gas_limit, kexit_info'
    GT
    // stack: out_of_gas, kexit_info'
    %jumpi(fault_exception)
    // stack: kexit_info'
%endmacro

// Charge gas. Faults if we exceed the limit for the current context,
// and prune context in case of an exception.
%macro charge_gas_and_prune
    // stack: gas, kexit_info, new_ctx, retdest
    %shl_const(192)
    ADD
    // stack: kexit_info', new_ctx
    %ctx_gas_limit
    // stack: gas_limit, kexit_info', new_ctx
    DUP2 %shr_const(192)
    // stack: gas_used, gas_limit, kexit_info', new_ctx
    GT
    // stack: out_of_gas, kexit_info', new_ctx
    %jumpi(fault_exception_and_prune)
    // stack: kexit_info', new_ctx
    SWAP1 POP
%endmacro

// Prunes previously created context before faulting.
global fault_exception_and_prune:
    // stack: kexit_info', new_ctx
    SWAP1 %prune_context
    // stack: kexit_info'
    %jump(fault_exception)

// Charge a constant amount of gas.
%macro charge_gas_const(gas)
    // stack: kexit_info
    PUSH $gas
    // stack: gas, kexit_info
    %charge_gas
    // stack: kexit_info'
%endmacro

// Charge gas and exit kernel code.
%macro charge_gas_and_exit
    // stack: gas, kexit_info
    %charge_gas
    // stack: kexit_info'
    EXIT_KERNEL
%endmacro

global sys_gasprice:
    // stack: kexit_info
    %charge_gas_const(@GAS_BASE)
    // stack: kexit_info
    %mload_txn_field(@TXN_FIELD_COMPUTED_FEE_PER_GAS)
    // stack: gas_price, kexit_info
    SWAP1
    EXIT_KERNEL

// Checks how much gas is remaining in this context, given the current kexit_info.
%macro leftover_gas
    // stack: kexit_info
    %shr_const(192)
    // stack: gas_used
    %mload_context_metadata(@CTX_METADATA_GAS_LIMIT)
    // stack: gas_limit, gas_used
    SWAP1
    // stack: gas_used, gas_limit
    DUP2 DUP2 LT
    // stack: gas_used < gas_limit, gas_used, gas_limit
    SWAP2
    // stack: gas_limit, gas_used, gas_used < gas_limit
    SUB
    // stack: gas_limit - gas_used, gas_used < gas_limit
    MUL
    // stack: leftover_gas = (gas_limit - gas_used) * (gas_used < gas_limit)
%endmacro

// Given the current kexit_info, drains all but one 64th of its remaining gas.
// Returns how much gas was drained.
%macro drain_all_but_one_64th_gas
    // stack: kexit_info, new_ctx
    DUP1 %leftover_gas
    // stack: leftover_gas, kexit_info, new_ctx
    %all_but_one_64th
    // stack: all_but_one_64th, kexit_info, new_ctx
    %stack (all_but_one_64th, kexit_info, new_ctx) -> (all_but_one_64th, kexit_info, new_ctx, all_but_one_64th)
    %charge_gas_and_prune
    // stack: kexit_info, drained_gas
%endmacro

// This is L(n), the "all but one 64th" function in the yellowpaper, i.e.
//     L(n) = n - floor(n / 64)
%macro all_but_one_64th
    // stack: n
    DUP1 %shr_const(6)
    // stack: floor(n / 64), n
    SWAP1 SUB
    // stack: n - floor(n / 64)
%endmacro
