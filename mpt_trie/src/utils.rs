//! Various types and logic that don't fit well into any other module.

use std::{
    borrow::Borrow,
    fmt::{self, Display},
    ops::BitAnd,
    sync::Arc,
};

use ethereum_types::H256;
use num_traits::PrimInt;

use crate::{
    nibbles::{Nibble, Nibbles, NibblesIntern},
    partial_trie::{Node, PartialTrie},
    trie_ops::TrieOpResult,
};

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
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

pub(crate) fn create_mask_of_1s(amt: usize) -> NibblesIntern {
    (NibblesIntern::one() << amt) - 1
}

pub(crate) fn bytes_to_h256(b: &[u8; 32]) -> H256 {
    keccak_hash::H256::from_slice(b)
}

/// Minimal key information of "segments" (nodes) used to construct trie
/// "traces" of a trie query. Unlike [`TrieNodeType`], this type also contains
/// the key piece of the node if applicable (eg. [`Node::Empty`] &
/// [`Node::Hash`] do not have associated key pieces).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TrieSegment {
    /// Empty node.
    Empty,

    /// Hash node.
    Hash,

    /// Branch node along with the nibble of the child taken.
    Branch(Nibble),

    /// Extension node along with the key piece of the node.
    Extension(Nibbles),

    /// Leaf node along with the key piece of the node.
    Leaf(Nibbles),
}

/// Trait for a type that can be converted into a trie key ([`Nibbles`]).
pub trait IntoTrieKey {
    /// Reconstruct the key of the type.
    fn into_key(self) -> Nibbles;
}

impl<P: Borrow<TrieSegment>, T: Iterator<Item = P>> IntoTrieKey for T {
    fn into_key(self) -> Nibbles {
        let mut key = Nibbles::default();

        for seg in self {
            match seg.borrow() {
                TrieSegment::Empty | TrieSegment::Hash => (),
                TrieSegment::Branch(nib) => key.push_nibble_back(*nib),
                TrieSegment::Extension(nibs) | TrieSegment::Leaf(nibs) => {
                    key.push_nibbles_back(nibs)
                }
            }
        }

        key
    }
}

/// A vector of path segments representing a path in the trie.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct TriePath(pub Vec<TrieSegment>);

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

impl IntoIterator for TriePath {
    type Item = TrieSegment;

    type IntoIter = <Vec<Self::Item> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<Vec<TrieSegment>> for TriePath {
    fn from(v: Vec<TrieSegment>) -> Self {
        Self(v)
    }
}

impl FromIterator<TrieSegment> for TriePath {
    fn from_iter<T: IntoIterator<Item = TrieSegment>>(iter: T) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl TriePath {
    /// Get an iterator of the individual path segments in the [`TriePath`].
    pub fn iter(&self) -> impl Iterator<Item = &'_ TrieSegment> {
        self.0.iter()
    }

    pub(crate) fn dup_and_append(&self, seg: TrieSegment) -> Self {
        let mut duped_vec = self.0.clone();
        duped_vec.push(seg);

        Self(duped_vec)
    }

    pub(crate) fn append(&mut self, seg: TrieSegment) {
        self.0.push(seg);
    }

    fn write_elem(f: &mut fmt::Formatter<'_>, seg: &TrieSegment) -> fmt::Result {
        write!(f, "{}", seg)
    }
}

impl Display for TrieSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrieSegment::Empty => write!(f, "Empty"),
            TrieSegment::Hash => write!(f, "Hash"),
            TrieSegment::Branch(nib) => write!(f, "Branch({})", nib),
            TrieSegment::Extension(nibs) => write!(f, "Extension({})", nibs),
            TrieSegment::Leaf(nibs) => write!(f, "Leaf({})", nibs),
        }
    }
}

impl TrieSegment {
    /// Get the node type of the [`TrieSegment`].
    pub const fn node_type(&self) -> TrieNodeType {
        match self {
            TrieSegment::Empty => TrieNodeType::Empty,
            TrieSegment::Hash => TrieNodeType::Hash,
            TrieSegment::Branch(_) => TrieNodeType::Branch,
            TrieSegment::Extension(_) => TrieNodeType::Extension,
            TrieSegment::Leaf(_) => TrieNodeType::Leaf,
        }
    }

    /// Extracts the key piece used by the segment (if applicable).
    pub(crate) fn get_key_piece_from_seg_if_present(&self) -> Option<Nibbles> {
        match self {
            TrieSegment::Empty | TrieSegment::Hash => None,
            TrieSegment::Branch(nib) => Some(Nibbles::from_nibble(*nib)),
            TrieSegment::Extension(nibs) | TrieSegment::Leaf(nibs) => Some(*nibs),
        }
    }
}

/// Creates a [`TrieSegment`] given a node and a key we are querying.
///
/// This function is intended to be used during a trie query as we are
/// traversing down a trie. Depending on the current node, we pop off nibbles
/// and use these to create `TrieSegment`s.
pub(crate) fn get_segment_from_node_and_key_piece<T: PartialTrie>(
    n: &Node<T>,
    k_piece: &Nibbles,
) -> TrieSegment {
    match TrieNodeType::from(n) {
        TrieNodeType::Empty => TrieSegment::Empty,
        TrieNodeType::Hash => TrieSegment::Hash,
        TrieNodeType::Branch => TrieSegment::Branch(k_piece.get_nibble(0)),
        TrieNodeType::Extension => TrieSegment::Extension(*k_piece),
        TrieNodeType::Leaf => TrieSegment::Leaf(*k_piece),
    }
}

/// Conversion from an [`Iterator`] within an allocator.
///
/// By implementing `TryFromIteratorIn` for a type, you define how it will be
/// created from an iterator. This is common for types which describe a
/// collection of some kind.
pub trait TryFromIterator<A>: Sized {
    /// Creates a value from an iterator within an allocator.
    fn try_from_iter<T: IntoIterator<Item = A>>(iter: T) -> TrieOpResult<Self>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{IntoTrieKey, TriePath, TrieSegment};
    use crate::nibbles::Nibbles;

    #[test]
    fn path_from_query_works() {
        let query_path: TriePath = vec![
            TrieSegment::Branch(1),
            TrieSegment::Branch(2),
            TrieSegment::Extension(0x34.into()),
            TrieSegment::Leaf(0x567.into()),
        ]
        .into();

        let reconstructed_key = query_path.iter().into_key();
        assert_eq!(reconstructed_key, Nibbles::from_str("0x1234567").unwrap());
    }
}
