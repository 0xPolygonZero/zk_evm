mod test_impls;

use zk_evm_proc_macro::{Columns, DerefColumns};

#[repr(C)]
pub struct NestedColumns<T> {
    x: T,
    y: [T; 3],
}

#[repr(C)]
#[derive(DerefColumns)]
pub struct OpColumns<T> {
    is_op_a: T,
    is_op_b: T,
    is_op_c: T,
}

#[repr(C)]
#[derive(Columns)]
pub struct AllColumns<T> {
    a: T,
    b: [T; 4],
    c: [NestedColumns<T>; 5],
    op: OpColumns<T>,
}
