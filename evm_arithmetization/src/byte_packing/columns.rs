//! Byte packing registers.

use std::mem::transmute;

use zk_evm_proc_macro::Columns;

use crate::{byte_packing::NUM_BYTES, util::indices_arr};

/// A view of `BytePackingStark`'s columns.
#[repr(C)]
#[derive(Columns, Eq, PartialEq, Debug)]
pub(crate) struct BytePackingColumnsView<T: Copy> {
    /// 1 if this is a READ operation, and 0 if this is a WRITE operation.
    pub is_read: T,

    // There are `NUM_BYTES` columns used to represent the length of
    // the input byte sequence for a (un)packing operation.
    // index_len[i] is 1 iff the length is i+1.
    pub index_len: [T; NUM_BYTES],

    pub addr_context: T,
    pub addr_segment: T,
    pub addr_virtual: T,
    pub timestamp: T,

    // 32 byte limbs hold a total of 256 bits.
    // There are `NUM_BYTES` columns used to store the values of the bytes
    // that are being read/written for an (un)packing operation.
    pub value_bytes: [T; NUM_BYTES],

    /// The counter column (used for the logUp range check) starts from 0 and
    /// increments.
    pub range_counter: T,
    /// The frequencies column used in logUp.
    pub rc_frequencies: T,
}

// `u8` is guaranteed to have a `size_of` of 1.
/// Number of columns in `BytePackingStark`.
pub(crate) const NUM_COLUMNS: usize = size_of::<BytePackingColumnsView<u8>>();

const fn make_col_map() -> BytePackingColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_COLUMNS>();
    unsafe { transmute::<[usize; NUM_COLUMNS], BytePackingColumnsView<usize>>(indices_arr) }
}

/// Map between the `BytePacking` columns and (0..`NUM_COLUMNS`)
pub(crate) const BYTE_PACKING_COL_MAP: BytePackingColumnsView<usize> = make_col_map();
