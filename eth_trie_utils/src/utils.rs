use std::ops::BitAnd;

use ethereum_types::U256;
use num_traits::PrimInt;

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U256 {
    (U256::one() << amt) - 1
}
