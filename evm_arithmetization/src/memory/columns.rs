//! Memory registers.

use std::mem::transmute;

use zk_evm_proc_macro::{Columns, DerefColumns};

use crate::{memory::VALUE_LIMBS, util::indices_arr};

/// Columns for the `MemoryStark`.
#[repr(C)]
#[derive(Columns, DerefColumns, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryColumnsView<T> {
    // Columns for memory operations, ordered by (addr, timestamp).
    /// 1 if this is an actual memory operation, or 0 if it's a padding row.
    pub filter: T,
    /// Each memory operation is associated to a unique timestamp.
    /// For a given memory operation `op_i`, its timestamp is computed as
    /// `C * N + i` where `C` is the CPU clock at that time, `N` is the number
    /// of general memory channels, and `i` is the index of the memory
    /// channel at which the memory operation is performed.
    pub timestamp: T,
    /// 1 if this is a read operation, 0 if it is a write one.
    pub is_read: T,
    /// The execution context of this address.
    pub addr_context: T,
    /// The segment section of this address.
    pub addr_segment: T,
    /// The virtual address within the given context and segment.
    pub addr_virtual: T,

    // Eight 32-bit limbs hold a total of 256 bits.
    // If a value represents an integer, it is little-endian encoded.
    pub value_limbs: [T; VALUE_LIMBS],

    // Flags to indicate whether this part of the address differs from the next row,
    // and the previous parts do not differ.
    // That is, e.g., `SEGMENT_FIRST_CHANGE` is `F::ONE` iff `ADDR_CONTEXT` is the
    // same in this row and the next, but `ADDR_SEGMENT` is not.
    pub context_first_change: T,
    pub segment_first_change: T,
    pub virtual_first_change: T,

    // Used to lower the degree of the zero-initializing constraints.
    // Contains `next_segment * addr_changed * next_is_read`.
    pub initialize_aux: T,

    // We use a range check to enforce the ordering.
    pub range_check: T,
    /// The counter column (used for the range check) starts from 0 and
    /// increments.
    pub counter: T,
    /// The frequencies column used in logUp.
    pub frequencies: T,
}

/// Total number of columns in `MemoryStark`.
/// `u8` is guaranteed to have a `size_of` of 1.
pub(crate) const NUM_COLUMNS: usize = core::mem::size_of::<MemoryColumnsView<u8>>();

/// Mapping between [0..NUM_COLUMNS-1] and the memory columns.
pub(crate) const MEMORY_COL_MAP: MemoryColumnsView<usize> = make_col_map();

const fn make_col_map() -> MemoryColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_COLUMNS>();
    unsafe { transmute::<[usize; NUM_COLUMNS], MemoryColumnsView<usize>>(indices_arr) }
}
