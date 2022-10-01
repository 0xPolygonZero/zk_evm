use std::{convert::TryInto, ops::BitAnd};

use ethereum_types::{U256, U512};
use num_traits::PrimInt;

use crate::partial_trie::Nibbles;

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U256 {
    ((U512::one() << amt) - 1).try_into().unwrap()
}

/// Creates nibbles that are easily readable for tests and logging.
/// Note that these nibbles are not fixed sized like the rest of the codebase.
pub(crate) fn nibbles_variable(k: u64) -> Nibbles {
    let mut n: Nibbles = Nibbles::from_u256_variable(k.into());
    n.count = Nibbles::get_num_nibbles_in_key(&(k.into()));

    n
}
