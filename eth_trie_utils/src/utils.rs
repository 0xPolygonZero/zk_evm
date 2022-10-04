use std::{convert::TryInto, ops::BitAnd};

use ethereum_types::{U256, U512};
use num_traits::PrimInt;

use crate::partial_trie::{Nibbles, PartialTrie};

#[derive(Debug)]
/// Simplified trie node type to make logging cleaner.
pub(crate) enum TrieNodeType {
    Empty,
    Hash,
    Branch,
    Extension,
    Leaf,
}

impl From<&PartialTrie> for TrieNodeType {
    fn from(node: &PartialTrie) -> Self {
        match node {
            PartialTrie::Empty => Self::Empty,
            PartialTrie::Hash(_) => Self::Hash,
            PartialTrie::Branch { .. } => Self::Branch,
            PartialTrie::Extension { .. } => Self::Extension,
            PartialTrie::Leaf { .. } => Self::Leaf,
        }
    }
}

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U256 {
    ((U512::one() << amt) - 1).try_into().unwrap()
}

// /// Creates nibbles that are easily readable for tests and logging.
// /// Note that these nibbles are not fixed sized like the rest of the codebase.
// pub(crate) fn nibbles_variable(k: u64) -> Nibbles {
//     let mut n: Nibbles = Nibbles::from_byte_be(k.to_be_bytes())
//     n.count = Nibbles::get_num_nibbles_in_key(&(k.into()));

//     n
// }

// pub(crate) fn num_leading_zero_bytes(bytes: &[u8]) -> usize {
//     bytes.iter().position(|b| *b != 0).map(|pos| pos + 1).unwrap_or_else(|| bytes.len())
// }
