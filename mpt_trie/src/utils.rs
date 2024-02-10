//! Various types and logic that don't fit well into any other module.

use std::{
    fmt::{self, Display},
    ops::BitAnd,
    sync::Arc,
};

use ethereum_types::{H256, U512};
use num_traits::PrimInt;

use crate::{
    nibbles::{Nibble, Nibbles},
    partial_trie::{Node, PartialTrie},
    special_query::TriePathIter,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
/// Simplified trie node type to make logging cleaner.
pub enum TrieNodeType {
    /// Empty node.
    Empty,

    /// Hash node.
    Hash,

    /// Branch node.
    Branch,

    /// Extension node.
    Extension,

    /// Leaf node.
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

/// Minimal key information of "segments" (nodes) used to construct trie
/// "traces" of a trie query. Unlike [`TrieNodeType`], this type also contains
/// the key piece of the node if applicable (eg. [`Node::Empty`] &
/// [`Node::Hash`] do not have associated key pieces).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum PathSegment {
    /// Empty node.
    Empty,

    /// Hash node.
    Hash,

    /// Branch node along with the nibble of the child taken.
    Branch(Nibble),

    /// Extension node along with the key piece of the node.
    Extension(Nibbles),

    /// Leaf node along wth the key piece of the node.
    Leaf(Nibbles),
}

/// A vector of path segments representing a path in the trie.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct TriePath(pub Vec<PathSegment>);

impl Display for TriePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let num_elems = self.0.len();

        // For everything but the last elem.
        for seg in self.0.iter().take(num_elems.saturating_sub(1)) {
            Self::write_elem(f, seg)?;
            write!(f, " --> ")?;
        }

        // Avoid the extra `-->` for the last elem.
        if let Some(seg) = self.0.last() {
            Self::write_elem(f, seg)?;
        }

        Ok(())
    }
}

impl TriePath {
    pub(crate) fn dup_and_append(&self, seg: PathSegment) -> Self {
        let mut duped_vec = self.0.clone();
        duped_vec.push(seg);

        Self(duped_vec)
    }

    pub(crate) fn append(&mut self, seg: PathSegment) {
        self.0.push(seg);
    }

    fn write_elem(f: &mut fmt::Formatter<'_>, seg: &PathSegment) -> fmt::Result {
        write!(f, "{}", seg)
    }
}

/// A trie path that is constructed lazily.
#[derive(Debug)]
pub struct TriePathLazy<T: PartialTrie>(TriePathIter<T>);

impl<T: PartialTrie> TriePathLazy<T> {
    /// Extract the key from the trie path.
    pub fn into_key(self) -> Nibbles {
        todo!()
    }
}

impl<T: PartialTrie> From<TriePathIter<T>> for TriePathLazy<T> {
    fn from(v: TriePathIter<T>) -> Self {
        Self(v)
    }
}

impl Display for PathSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathSegment::Empty => write!(f, "Empty"),
            PathSegment::Hash => write!(f, "Hash"),
            PathSegment::Branch(nib) => write!(f, "Branch({})", nib),
            PathSegment::Extension(nibs) => write!(f, "Extension({})", nibs),
            PathSegment::Leaf(nibs) => write!(f, "Leaf({})", nibs),
        }
    }
}

impl PathSegment {
    /// Get the node type of the [`PathSegment`].
    pub fn node_type(&self) -> TrieNodeType {
        match self {
            PathSegment::Empty => TrieNodeType::Empty,
            PathSegment::Hash => TrieNodeType::Hash,
            PathSegment::Branch(_) => TrieNodeType::Branch,
            PathSegment::Extension(_) => TrieNodeType::Extension,
            PathSegment::Leaf(_) => TrieNodeType::Leaf,
        }
    }

    /// Extracts the key piece used by the segment (if applicable).
    pub fn get_key_piece_from_seg_if_present(&self) -> Option<Nibbles> {
        match self {
            PathSegment::Empty | PathSegment::Hash => None,
            PathSegment::Branch(nib) => Some(Nibbles::from_nibble(*nib)),
            PathSegment::Extension(nibs) | PathSegment::Leaf(nibs) => Some(*nibs),
        }
    }
}

/// Creates a [`PathSegment`] given a node and a key we are querying.
///
/// This function is intended to be used during a trie query as we are
/// traversing down a trie. Depending on the current node, we pop off nibbles
/// and use these to create `PathSegment`s.
pub fn get_segment_from_node_and_key_piece<T: PartialTrie>(
    n: &Node<T>,
    k_piece: &Nibbles,
) -> PathSegment {
    match TrieNodeType::from(n) {
        TrieNodeType::Empty => PathSegment::Empty,
        TrieNodeType::Hash => PathSegment::Hash,
        TrieNodeType::Branch => PathSegment::Branch(k_piece.get_nibble(0)),
        TrieNodeType::Extension => PathSegment::Extension(*k_piece),
        TrieNodeType::Leaf => PathSegment::Leaf(*k_piece),
    }
}
