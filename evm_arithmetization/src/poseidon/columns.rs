use std::mem::{size_of, transmute};

use plonky2::hash::poseidon;
use zk_evm_proc_macro::Columns;

use super::poseidon_stark::FELT_MAX_BYTES;
use crate::util::indices_arr;

pub(crate) const POSEIDON_SPONGE_WIDTH: usize = poseidon::SPONGE_WIDTH;
pub(crate) const POSEIDON_SPONGE_RATE: usize = poseidon::SPONGE_RATE;
pub(crate) const HALF_N_FULL_ROUNDS: usize = poseidon::HALF_N_FULL_ROUNDS;
pub(crate) const N_PARTIAL_ROUNDS: usize = poseidon::N_PARTIAL_ROUNDS;
pub(crate) const POSEIDON_DIGEST: usize = 4;

#[repr(C)]
#[derive(Columns, Eq, PartialEq, Debug)]
pub(crate) struct PoseidonColumnsView<T: Copy> {
    // The base address at which we will read the input block.
    pub context: T,
    pub segment: T,
    pub virt: T,

    /// The timestamp at which Poseidon is called.
    pub timestamp: T,

    /// The length of the original input for `PoseidonGeneralOp`. 0 for
    /// `PoseidonSimpleOp`.
    pub len: T,
    /// The number of elements that have already been absorbed prior
    /// to this block.
    pub already_absorbed_elements: T,

    /// If this row represents a final block row, the `i`th entry should be 1 if
    /// the final chunk of input has length `i` (in other words if `len -
    /// already_absorbed == i`), otherwise 0.
    ///
    /// If this row represents a full input block, this should contain all 0s.
    pub is_final_input_len: [T; POSEIDON_SPONGE_RATE],

    /// 1 if this row represents a full input block, i.e. one in which each
    /// element is an input element, not a padding element; 0 otherwise.
    pub is_full_input_block: T,

    /// Registers to hold permutation inputs.
    pub input: [T; POSEIDON_SPONGE_WIDTH],

    /// Holds x^3 for all elements in full rounds.
    pub cubed_full: [T; 2 * HALF_N_FULL_ROUNDS * POSEIDON_SPONGE_WIDTH],

    /// Holds x^3 for the first element in partial rounds.
    pub cubed_partial: [T; N_PARTIAL_ROUNDS],

    /// Holds the input of the `i`-th S-box of the `round`-th round of the first
    /// set of full rounds.
    pub full_sbox_0: [T; POSEIDON_SPONGE_WIDTH * (HALF_N_FULL_ROUNDS - 1)],

    /// Holds the input of the S-box of the `round`-th round of the partial
    /// rounds.
    pub partial_sbox: [T; N_PARTIAL_ROUNDS],

    /// Holds the input of the `i`-th S-box of the `round`-th round of the
    /// second set of full rounds.
    pub full_sbox_1: [T; POSEIDON_SPONGE_WIDTH * HALF_N_FULL_ROUNDS],

    /// The digest, with each element divided into two 32-bit limbs.
    pub digest: [T; 2 * POSEIDON_DIGEST],

    /// The output of the hash function with the digest removed.
    pub output_partial: [T; POSEIDON_SPONGE_WIDTH - POSEIDON_DIGEST],

    /// Holds the pseudo-inverse of (digest_high_limb_i - 2^32 + 1).
    pub pinv: [T; POSEIDON_DIGEST],

    /// Holds the byte decomposition of the input, except for the less
    /// significant byte.
    pub input_bytes: [[T; FELT_MAX_BYTES - 1]; POSEIDON_SPONGE_RATE],

    /// Indicates if this is a simple operation where inputs are
    /// read from the top of the stack.
    pub is_simple_op: T,

    /// Indicates if this is the first row of a general operation.
    pub is_first_row_general_op: T,

    pub not_padding: T,
}

/// Returns the index the `i`-th x^3 in the `round`-th round for full rounds.
/// Note: the cubes of the two sets of full rounds are stored one after the
/// other.
pub(crate) fn reg_cubed_full(round: usize, i: usize) -> usize {
    debug_assert!(i < POSEIDON_SPONGE_WIDTH);
    debug_assert!(round < 2 * HALF_N_FULL_ROUNDS);
    POSEIDON_SPONGE_WIDTH * round + i
}

/// Returns the index of x^3 within for the `round`-th partial round.
pub(crate) fn reg_cubed_partial(round: usize) -> usize {
    debug_assert!(round < N_PARTIAL_ROUNDS);
    round
}

/// Returns the index of the `i`-th input in the `round`-th round within
/// `full_sbox_0`.
pub(crate) fn reg_full_sbox_0(round: usize, i: usize) -> usize {
    debug_assert!(
        round != 0,
        "First round S-box inputs are not stored as wires"
    );
    debug_assert!(round < HALF_N_FULL_ROUNDS);
    debug_assert!(i < POSEIDON_SPONGE_WIDTH);
    POSEIDON_SPONGE_WIDTH * (round - 1) + i
}

/// Returns the index of the input of the S-box of the `round`-th round of the
/// partial rounds.
pub(crate) fn reg_partial_sbox(round: usize) -> usize {
    debug_assert!(round < N_PARTIAL_ROUNDS);
    round
}

/// Returns the index of the `i`-th input in the `round`-th round within
/// `full_sbox_1`.
pub(crate) fn reg_full_sbox_1(round: usize, i: usize) -> usize {
    debug_assert!(round < HALF_N_FULL_ROUNDS);
    debug_assert!(i < POSEIDON_SPONGE_WIDTH);
    POSEIDON_SPONGE_WIDTH * round + i
}

// `u8` is guaranteed to have a `size_of` of 1.
pub(crate) const NUM_COLUMNS: usize = size_of::<PoseidonColumnsView<u8>>();

const fn make_col_map() -> PoseidonColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_COLUMNS>();
    unsafe { transmute::<[usize; NUM_COLUMNS], PoseidonColumnsView<usize>>(indices_arr) }
}

pub(crate) const POSEIDON_COL_MAP: PoseidonColumnsView<usize> = make_col_map();
