use zk_evm_proc_macro::{Columns, DerefColumns};

/// Structure representing the flags for the various opcodes.
#[repr(C)]
#[derive(Columns, DerefColumns, Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) struct OpsColumnsView<T: Copy> {
    /// Combines ADD, MUL, SUB, DIV, MOD, LT, GT and BYTE flags.
    pub binary_op: T,
    /// Combines ADDMOD, MULMOD and SUBMOD flags.
    pub ternary_op: T,
    /// Combines ADD_FP254, MUL_FP254 and SUB_FP254 flags.
    pub fp254_op: T,
    /// Combines EQ and ISZERO flags.
    pub eq_iszero: T,
    /// Combines AND, OR and XOR flags.
    pub logic_op: T,
    /// Combines NOT and POP flags.
    pub not_pop: T,
    /// Combines SHL and SHR flags.
    pub shift: T,
    /// Combines JUMPDEST and KECCAK_GENERAL flags.
    pub jumpdest_keccak_general: T,
    /// Combines POSEIDON and POSEIDON_GENERAL flags.
    pub poseidon: T,
    /// Combines JUMP and JUMPI flags.
    pub jumps: T,
    /// Combines PUSH and PROVER_INPUT flags.
    pub push_prover_input: T,
    /// Combines DUP and SWAP flags.
    pub dup_swap: T,
    /// Combines GET_CONTEXT and SET_CONTEXT flags.
    pub context_op: T,
    /// Combines MSTORE_32BYTES and MLOAD_32BYTES.
    pub m_op_32bytes: T,
    /// Flag for EXIT_KERNEL.
    pub exit_kernel: T,
    /// Combines MSTORE_GENERAL and MLOAD_GENERAL flags.
    pub m_op_general: T,
    /// Combines PC and PUSH0
    pub pc_push0: T,

    /// Flag for syscalls.
    pub syscall: T,
    /// Flag for exceptions.
    pub exception: T,
}
