use std::fmt::{self, Display};

use crate::{
    nibbles::{Nibble, Nibbles},
    partial_trie::{Node, PartialTrie},
    utils::TrieNodeType,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) enum PathSegment {
    Empty,
    Hash,
    Branch(Nibble),
    Extension(Nibbles),
    Leaf(Nibbles),
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
    pub(super) fn node_type(&self) -> TrieNodeType {
        match self {
            PathSegment::Empty => TrieNodeType::Empty,
            PathSegment::Hash => TrieNodeType::Hash,
            PathSegment::Branch(_) => TrieNodeType::Branch,
            PathSegment::Extension(_) => TrieNodeType::Extension,
            PathSegment::Leaf(_) => TrieNodeType::Leaf,
        }
    }

    pub(super) fn get_key_piece_from_seg_if_present(&self) -> Option<Nibbles> {
        match self {
            PathSegment::Empty | PathSegment::Hash => None,
            PathSegment::Branch(nib) => Some(Nibbles::from_nibble(*nib)),
            PathSegment::Extension(nibs) | PathSegment::Leaf(nibs) => Some(*nibs),
        }
    }
}

pub(super) fn get_segment_from_node_and_key_piece<T: PartialTrie>(
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

/// Get the key piece from the given node if applicable.
///
/// Note that there is no specific [`Nibble`] associated with a branch like
/// there are [`Nibbles`] with [Extension][`Node::Extension`] and
/// [Leaf][`Node::Leaf`] nodes, and the only way to get the `Nibble`
/// "associated" with a branch is to look at the next `Nibble` in the current
/// key as we traverse down it.
pub(super) fn get_key_piece_from_node_pulling_from_key_for_branches<T: PartialTrie>(
    n: &Node<T>,
    curr_key: &Nibbles,
) -> Nibbles {
    match n {
        Node::Empty | Node::Hash(_) => Nibbles::default(),
        Node::Branch { .. } => curr_key.get_next_nibbles(1),
        Node::Extension { nibbles, child: _ } | Node::Leaf { nibbles, value: _ } => *nibbles,
    }
}

/// Get the key piece from the given node if applicable. Note that
/// [branch][`Node::Branch`]s have no [`Nibble`] directly associated with them.
pub(super) fn get_key_piece_from_node<T: PartialTrie>(n: &Node<T>) -> Nibbles {
    match n {
        Node::Empty | Node::Hash(_) | Node::Branch { .. } => Nibbles::default(),
        Node::Extension { nibbles, child: _ } | Node::Leaf { nibbles, value: _ } => *nibbles,
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct NodePath(pub(super) Vec<PathSegment>);

impl NodePath {
    pub(super) fn dup_and_append(&self, seg: PathSegment) -> Self {
        let mut duped_vec = self.0.clone();
        duped_vec.push(seg);

        Self(duped_vec)
    }

    pub(super) fn append(&mut self, seg: PathSegment) {
        self.0.push(seg);
    }

    fn write_elem(f: &mut fmt::Formatter<'_>, seg: &PathSegment) -> fmt::Result {
        write!(f, "{}", seg)
    }
}

impl Display for NodePath {
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
