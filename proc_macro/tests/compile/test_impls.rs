use core::borrow::{Borrow, BorrowMut};
use core::ops::{Deref, DerefMut, Index, IndexMut};

use super::*;

const NUM_OP_COLUMNS: usize = core::mem::size_of::<OpColumns<u8>>();

#[allow(unused)]
trait TestDerefColumns<T>: Deref<Target = [T; NUM_OP_COLUMNS]> + DerefMut {}
impl<T: Copy> TestDerefColumns<T> for OpColumns<T> {}

const NUM_COLUMNS: usize = core::mem::size_of::<AllColumns<u8>>();

#[allow(unused)]
trait TestColumns<T, I>:
    Borrow<[T; NUM_COLUMNS]>
    + BorrowMut<[T; NUM_COLUMNS]>
    + From<[T; NUM_COLUMNS]>
    + Index<I, Output = <[T] as Index<I>>::Output>
    + IndexMut<I>
    + Default
where
    [T]: Index<I> + IndexMut<I>,
    [T; NUM_COLUMNS]: Borrow<Self>,
    [T; NUM_COLUMNS]: BorrowMut<Self>,
    [T; NUM_COLUMNS]: From<Self>,
{
}
impl<T, I> TestColumns<T, I> for AllColumns<T>
where
    T: Copy + Default,
    [T]: Index<I> + IndexMut<I>,
{
}
