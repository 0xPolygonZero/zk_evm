//! The MemAfter STARK is used to store the memory state at the end of the
//! execution. It connects to the memory STARK to read the final values of all
//! touched addresses.

pub mod columns;
pub mod memory_continuation_stark;
