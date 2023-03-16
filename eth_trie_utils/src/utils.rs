use std::{convert::TryInto, fmt::Display, ops::BitAnd, sync::Arc};

use ethereum_types::{U256, U512};
use num_traits::PrimInt;

use crate::partial_trie::{Node, TrieNode};

#[derive(Debug)]
/// Simplified trie node type to make logging cleaner.
pub(crate) enum TrieNodeType {
    Empty,
    Hash,
    Branch,
    Extension,
    Leaf,
}

impl<N: TrieNode> From<&Arc<Box<N>>> for TrieNodeType {
    fn from(value: &Arc<Box<N>>) -> Self {
        (&****value).into()
    }
}

impl<N: TrieNode> From<&Node<N>> for TrieNodeType {
    fn from(node: &Node<N>) -> Self {
        match node {
            Node::Empty => Self::Empty,
            Node::Hash(_) => Self::Hash,
            Node::Branch { .. } => Self::Branch,
            Node::Extension { .. } => Self::Extension,
            Node::Leaf { .. } => Self::Leaf,
        }
    }
}

impl Display for TrieNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrieNodeType::Empty => write!(f, "Empty"),
            TrieNodeType::Hash => write!(f, "Hash"),
            TrieNodeType::Branch => write!(f, "Branch"),
            TrieNodeType::Extension => write!(f, "Extension"),
            TrieNodeType::Leaf => write!(f, "Leaf"),
        }
    }
}

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U256 {
    ((U512::one() << amt) - 1).try_into().unwrap()
}
