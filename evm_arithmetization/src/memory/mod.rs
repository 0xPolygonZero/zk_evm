//! The Memory STARK is used to handle all memory read and write operations
//! happening when executing the EVM. Each non-dummy row of the table correspond
//! to a single operation, and rows are ordered by the timestamp associated to
//! each memory operation.

pub mod columns;
pub mod memory_stark;
pub mod segments;

/// The number of limbs holding the value at a memory address.
/// Eight limbs of 32 bits can hold a `U256`.
pub(crate) const VALUE_LIMBS: usize = 8;
