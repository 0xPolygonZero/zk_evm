use std::{convert::TryInto, ops::BitAnd};

use ethereum_types::{U256, U512};
use num_traits::PrimInt;

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U256 {
    ((U512::one() << amt) - 1).try_into().unwrap()
}

pub(crate) fn u256_as_hex_string(v: &U256) -> String {
    let mut byte_buf = [0; 32];
    v.to_big_endian(&mut byte_buf);
    format!("0x{}", hex::encode(byte_buf))
}
