//! Hardcoded circuit constants to be used when generating the prover circuits.

use core::ops::Range;

/// Default range to be used for the `ArithmeticStark` table.
pub(crate) const DEFAULT_ARITHMETIC_RANGE: Range<usize> = 16..28;
/// Default range to be used for the `BytePackingStark` table.
pub(crate) const DEFAULT_BYTE_PACKING_RANGE: Range<usize> = 9..28;
/// Default range to be used for the `CpuStark` table.
pub(crate) const DEFAULT_CPU_RANGE: Range<usize> = 12..28;
/// Default range to be used for the `KeccakStark` table.
pub(crate) const DEFAULT_KECCAK_RANGE: Range<usize> = 14..25;
/// Default range to be used for the `KeccakSpongeStark` table.
pub(crate) const DEFAULT_KECCAK_SPONGE_RANGE: Range<usize> = 9..25;
/// Default range to be used for the `LogicStark` table.
pub(crate) const DEFAULT_LOGIC_RANGE: Range<usize> = 12..28;
/// Default range to be used for the `MemoryStark` table.
pub(crate) const DEFAULT_MEMORY_RANGE: Range<usize> = 17..30;
