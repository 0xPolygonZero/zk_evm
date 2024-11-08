global sys_balance:
    // stack: kexit_info, address
    SWAP1 %u256_to_addr
    // stack: address, kexit_info
    SWAP1
    DUP2 %insert_accessed_addresses
    // stack: cold_access, kexit_info, address
    PUSH @GAS_COLDACCOUNTACCESS_MINUS_WARMACCESS
    MUL
    PUSH @GAS_WARMACCESS
    ADD
    %charge_gas
    // stack: kexit_info, address

    SWAP1
    // stack: address, kexit_info
    %balance
    // stack: balance, kexit_info
    SWAP1
    EXIT_KERNEL

%macro balance
    %stack (address) -> (address, %%after)
    %jump(balance)
%%after:
%endmacro

global balance:
    // stack: address, retdest
    %read_balance
    // stack: balance, retdest
    SWAP1 JUMP

global sys_selfbalance:
    // stack: kexit_info
    %charge_gas_const(@GAS_LOW)
    %selfbalance
    // stack: balance, kexit_info
    SWAP1
    EXIT_KERNEL

%macro selfbalance
    PUSH %%after
    %address
    %jump(balance)
%%after:
%endmacro
