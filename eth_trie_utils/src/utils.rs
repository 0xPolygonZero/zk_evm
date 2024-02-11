use std::{fmt::Display, ops::BitAnd, sync::Arc};

use ethereum_types::{H256, U512};
use num_traits::PrimInt;

use crate::partial_trie::{Node, PartialTrie};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// Simplified trie node type to make logging cleaner.
pub(crate) enum TrieNodeType {
    Empty,
    Hash,
    Branch,
    Extension,
    Leaf,
}

impl<N: PartialTrie> From<&Arc<Box<N>>> for TrieNodeType {
    fn from(value: &Arc<Box<N>>) -> Self {
        (&****value).into()
    }
}

impl<N: PartialTrie> From<&Node<N>> for TrieNodeType {
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
        let s = match self {
            TrieNodeType::Empty => "Empty",
            TrieNodeType::Hash => "Hash",
            TrieNodeType::Branch => "Branch",
            TrieNodeType::Extension => "Extension",
            TrieNodeType::Leaf => "Leaf",
        };

        write!(f, "{}", s)
    }
}

pub(crate) fn is_even<T: PrimInt + BitAnd<Output = T>>(num: T) -> bool {
    (num & T::one()) == T::zero()
}

pub(crate) fn create_mask_of_1s(amt: usize) -> U512 {
    (U512::one() << amt) - 1
}

pub(crate) fn bytes_to_h256(b: &[u8; 32]) -> H256 {
    keccak_hash::H256::from_slice(b)
}
