use std::{convert::TryInto, ops::BitAnd};

use ethereum_types::{U256, U512};
use num_traits::PrimInt;

use crate::partial_trie::PartialTrie;

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
