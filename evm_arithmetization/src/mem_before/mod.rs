//! The MemBefore STARK is used to store the memory state from the previous
//! proof.. It connects to the memory STARK to write to all its addresses at
//! timestamp 0.

pub mod columns;
pub mod mem_before_stark;
