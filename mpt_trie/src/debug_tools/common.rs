//! Common utilities for the debugging tools.
use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie},
};

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
