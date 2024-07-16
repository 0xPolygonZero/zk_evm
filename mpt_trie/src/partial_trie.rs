//! Definitions for the core types [`PartialTrie`] and [`Nibbles`].

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use ethereum_types::H256;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{
    nibbles::Nibbles,
    trie_hashing::{hash_trie, rlp_encode_and_hash_node, EncodedNode},
    trie_ops::{TrieOpResult, ValOrHash},
    utils::{bytes_to_h256, TryFromIterator},
};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
/// A partial trie, or a sub-trie thereof. This mimics the structure of an
/// Ethereum trie, except with an additional `Hash` node type, representing a
/// node whose data is not needed to process our transaction.
pub enum Node {
    /// An empty trie.
    #[default]
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
        /// A slice containing the 16 children of this branch node.
        children: [Box<Self>; 16],
        /// The payload of this node.
        value: Vec<u8>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        /// The path of this extension.
        nibbles: Nibbles,
        /// The child of this extension node.
        child: Box<Self>,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf {
        /// The path of this leaf node.
        nibbles: Nibbles,
        /// The payload of this node
        value: Vec<u8>,
    },
}

/// A partial trie that lazily caches hashes for each node as needed.
/// If you are doing frequent hashing of node, you probably want to use this
/// `Trie` variant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HashedPartialTrie {
    pub(crate) root: Node,
    pub(crate) hash: Arc<RwLock<Option<H256>>>,
}

impl HashedPartialTrie {
    /// Lazily get calculates the hash for the node,
    pub(crate) fn get_hash(&self) -> H256 {
        let hash = *self.hash.read();

        match hash {
            Some(h) => h,
            None => hash_trie(self),
        }
    }

    pub(crate) fn set_hash(&self, v: Option<H256>) {
        *self.hash.write() = v;
    }
}

impl HashedPartialTrie {
    /// Creates a new partial trie from a node.
    pub fn new(node: Node) -> Self {
        Self {
            root: node,
            hash: Arc::new(RwLock::new(None)),
        }
    }
    /// Inserts a node into the trie.
    pub fn insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
    {
        self.root.trie_insert(k, v)?;
        self.set_hash(None);
        Ok(())
    }
    /// Add more nodes to the trie through an iterator
    pub fn extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.root.trie_extend(nodes)?;
        self.set_hash(None);
        Ok(())
    }
    /// Get a node if it exists in the trie.
    pub fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        self.root.trie_get(k)
    }

    /// Deletes a `Leaf` node or `Branch` value field if it exists.
    ///
    /// To agree with Ethereum specs, deleting nodes does not result in the trie
    /// removing nodes that are redundant after deletion. For example, a
    /// `Branch` node that is completely empty after all of its children are
    /// deleted is not pruned. Also note:
    /// - Deleted leaves are replaced with `Empty` nodes.
    /// - Deleted branch values are replaced with empty `Vec`s.
    ///
    /// # Panics
    /// If a `Hash` node is traversed, a panic will occur. Since `Hash` nodes
    /// are meant for parts of the trie that are not relevant, traversing one
    /// means that a `Hash` node was created that potentially should not have
    /// been.
    pub fn delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        let res = self.root.trie_delete(k);
        self.set_hash(None);

        res
    }
    /// Get the hash for the node.
    pub fn hash(&self) -> H256 {
        self.get_hash()
    }
    /// Returns an iterator over the trie that returns all key/value pairs for
    /// every `Leaf` and `Hash` node.
    pub fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.root.trie_items()
    }
    /// Returns an iterator over the trie that returns all keys for every `Leaf`
    /// and `Hash` node.
    pub fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.root.trie_keys()
    }
    /// Returns an iterator over the trie that returns all values for every
    /// `Leaf` and `Hash` node.
    pub fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.root.trie_values()
    }
    /// Returns `true` if the trie contains an element with the given key.
    pub fn contains<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>,
    {
        self.root.trie_has_item_by_key(k)
    }
}

impl Node {
    pub(crate) fn hash_intern(&self) -> EncodedNode {
        let res = rlp_encode_and_hash_node(&self);
        res
    }
    pub(crate) fn get_hash(&self) -> H256 {
        hash_trie(self)
    }
}

impl Deref for HashedPartialTrie {
    type Target = Node;

    fn deref(&self) -> &Self::Target {
        &self.root
    }
}

impl DerefMut for HashedPartialTrie {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.root
    }
}

impl Eq for HashedPartialTrie {}
impl PartialEq for HashedPartialTrie {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
    }
}

impl<K, V> TryFromIterator<(K, V)> for HashedPartialTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn try_from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> TrieOpResult<Self> {
        let mut root = Node::Empty;
        root.extend(nodes)?;
        Ok(root)
    }
}
