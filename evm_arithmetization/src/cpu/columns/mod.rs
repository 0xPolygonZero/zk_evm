use core::borrow::{Borrow, BorrowMut};
use core::fmt::Debug;
use core::mem::{size_of, transmute};
use core::ops::{Index, IndexMut};

use plonky2::field::types::Field;
use zk_evm_proc_macro::Columns;

use crate::cpu::columns::general::CpuGeneralColumnsView;
use crate::cpu::columns::ops::OpsColumnsView;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::memory;
use crate::util::indices_arr;

mod general;
/// Cpu operation flags.
pub(crate) mod ops;

/// 32-bit limbs of the value stored in the current memory channel.
pub type MemValue<T> = [T; memory::VALUE_LIMBS];

/// View of the columns required for one memory channel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MemoryChannelView<T: Copy> {
    /// 1 if this row includes a memory operation in the `i`th channel of the
    /// memory bus, otherwise 0.
    pub used: T,
    /// 1 if a read is performed on the `i`th channel of the memory bus,
    /// otherwise 0.
    pub is_read: T,
    /// Context of the memory operation in the `i`th channel of the memory bus.
    pub addr_context: T,
    /// Segment of the memory operation in the `ith` channel of the memory bus.
    pub addr_segment: T,
    /// Virtual address of the memory operation in the `ith` channel of the
    /// memory bus.
    pub addr_virtual: T,
    /// Value, subdivided into 32-bit limbs, stored in the `ith` channel of the
    /// memory bus.
    pub value: MemValue<T>,
}

/// View of all the columns in `CpuStark`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// A more lightweight channel, sharing values with the 0-th memory channel
// (which contains the top of the stack).
pub(crate) struct PartialMemoryChannelView<T: Copy> {
    pub used: T,
    pub is_read: T,
    pub addr_context: T,
    pub addr_segment: T,
    pub addr_virtual: T,
}

#[repr(C)]
#[derive(Columns, Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) struct CpuColumnsView<T: Copy> {
    /// If CPU cycle: Current context.
    pub context: T,

    /// If CPU cycle: Context for code memory channel.
    pub code_context: T,

    /// If CPU cycle: The program counter for the current instruction.
    pub program_counter: T,

    /// If CPU cycle: The stack length.
    pub stack_len: T,

    /// If CPU cycle: We're in kernel (privileged) mode.
    pub is_kernel_mode: T,

    /// If CPU cycle: Gas counter.
    pub gas: T,

    /// If CPU cycle: flags for EVM instructions (a few cannot be shared; see
    /// the comments in `OpsColumnsView`).
    pub op: OpsColumnsView<T>,

    /// If CPU cycle: the opcode, broken up into bits in little-endian order.
    pub opcode_bits: [T; 8],

    /// Columns shared by various operations.
    pub(crate) general: CpuGeneralColumnsView<T>,

    /// CPU clock.
    pub(crate) clock: T,

    /// Memory bus channels in the CPU.
    /// Full channels are comprised of 13 columns.
    pub mem_channels: [MemoryChannelView<T>; NUM_GP_CHANNELS],
    /// Partial channel is only comprised of 5 columns.
    pub(crate) partial_channel: PartialMemoryChannelView<T>,
}

/// Total number of columns in `CpuStark`.
/// `u8` is guaranteed to have a `size_of` of 1.
pub(crate) const NUM_CPU_COLUMNS: usize = size_of::<CpuColumnsView<u8>>();

const fn make_col_map() -> CpuColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLUMNS>();
    unsafe { transmute::<[usize; NUM_CPU_COLUMNS], CpuColumnsView<usize>>(indices_arr) }
}

/// Mapping between [0..NUM_CPU_COLUMNS-1] and the CPU columns.
pub(crate) const COL_MAP: CpuColumnsView<usize> = make_col_map();
