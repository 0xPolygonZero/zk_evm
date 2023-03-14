//! Definitions for the core types [`PartialTrie`] and [`Nibbles`].

use std::{fmt::Debug, sync::Arc};

use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::nibbles::Nibbles;

/// Alias for a node that is a child of an extension or branch node.
pub type WrappedNode = Arc<Box<PartialTrie>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
/// A partial trie, or a sub-trie thereof. This mimics the structure of an
/// Ethereum trie, except with an additional `Hash` node type, representing a
/// node whose data is not needed to process our transaction.
pub enum PartialTrie {
    /// An empty trie.
    Empty,
    /// The digest of trie whose data does not need to be stored.
    ///
    /// **Important note**: Hash nodes should **only** be created to replace
    /// `PartialTrie`s whose RLP encoding is >= 32 bytes. Creating a hash node
    /// for a `PartialTrie` smaller than this will cause an incorrect hash to be
    /// generated for the trie.
    Hash(H256),
    /// A branch node, which consists of 16 children and an optional value.
    Branch {
        children: [WrappedNode; 16],
        value: Vec<u8>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        nibbles: Nibbles,
        child: WrappedNode,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf { nibbles: Nibbles, value: Vec<u8> },
}

impl From<PartialTrie> for WrappedNode {
    fn from(v: PartialTrie) -> Self {
        Arc::new(Box::new(v))
    }
}

impl Eq for PartialTrie {}

/// `PartialTrie` equality means all nodes through the trie are equivalent.
impl PartialEq for PartialTrie {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PartialTrie::Empty, PartialTrie::Empty) => true,
            (PartialTrie::Hash(h1), PartialTrie::Hash(h2)) => h1 == h2,
            (
                PartialTrie::Branch {
                    children: c1,
                    value: v1,
                },
                PartialTrie::Branch {
                    children: c2,
                    value: v2,
                },
            ) => v1 == v2 && (0..16).all(|i| c1[i] == c2[i]),
            (
                PartialTrie::Extension {
                    nibbles: n1,
                    child: c1,
                },
                PartialTrie::Extension {
                    nibbles: n2,
                    child: c2,
                },
            ) => n1 == n2 && c1 == c2,
            (
                PartialTrie::Leaf {
                    nibbles: n1,
                    value: v1,
                },
                PartialTrie::Leaf {
                    nibbles: n2,
                    value: v2,
                },
            ) => n1 == n2 && v1 == v2,
            (_, _) => false,
        }
    }
}

impl Default for PartialTrie {
    fn default() -> Self {
        Self::Empty
    }
}
