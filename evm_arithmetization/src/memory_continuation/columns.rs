//! Columns for the initial or final memory, ordered by address.
//! It contains (addr, value) pairs. Note that non-padding addresses must be
//! unique.
use crate::memory::VALUE_LIMBS;

/// 1 if an actual value or 0 if it's a padding row.
pub(crate) const FILTER: usize = 0;
/// The execution context of the address.
pub(crate) const ADDR_CONTEXT: usize = FILTER + 1;
/// The segment section of this address.
pub(crate) const ADDR_SEGMENT: usize = ADDR_CONTEXT + 1;
/// The virtual address within the given context and segment.
pub(crate) const ADDR_VIRTUAL: usize = ADDR_SEGMENT + 1;

// Eight 32-bit limbs hold a total of 256 bits.
// If a value represents an integer, it is little-endian encoded.
const VALUE_START: usize = ADDR_VIRTUAL + 1;
pub(crate) const fn value_limb(i: usize) -> usize {
    debug_assert!(i < VALUE_LIMBS);
    VALUE_START + i
}

pub(crate) const NUM_COLUMNS: usize = VALUE_START + VALUE_LIMBS;
