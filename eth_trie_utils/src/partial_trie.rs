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
    trie_ops::ValOrHash,
};

/// Alias for a node that is a child of an extension or branch node.
pub type WrappedNode<N> = Arc<Box<N>>;

impl<N: PartialTrie> AsRef<Node<N>> for WrappedNode<N> {
    fn as_ref(&self) -> &Node<N> {
        self
    }
}

impl<N: PartialTrie> From<Node<N>> for WrappedNode<N> {
    fn from(v: Node<N>) -> Self {
        Arc::new(Box::new(N::new(v)))
    }
}

/// A trait for any types that are `PartialTrie`s.
pub trait PartialTrie:
    Clone
    + Debug
    + Default
    + Deref<Target = Node<Self>>
    + DerefMut<Target = Node<Self>>
    + Eq
    + PartialEq
    + Sized
{
    fn new(n: Node<Self>) -> Self;

    /// Inserts a node into the trie.
    fn insert<K, V>(&mut self, k: K, v: V)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>;

    /// Add more nodes to the trie through an iterator
    fn extend<K, V, I>(&mut self, nodes: I)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
        I: IntoIterator<Item = (K, V)>;

    /// Get a node if it exists in the trie.
    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<Nibbles>;

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
    fn delete<K>(&mut self, k: K) -> Option<Vec<u8>>
    where
        K: Into<Nibbles>;

    /// Get the hash for the node.
    fn hash(&self) -> H256;

    /// Returns an iterator over the trie that returns all key/value pairs for
    /// every `Leaf` and `Hash` node.
    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)>;

    /// Returns an iterator over the trie that returns all keys for every `Leaf`
    /// and `Hash` node.
    fn keys(&self) -> impl Iterator<Item = Nibbles>;

    /// Returns an iterator over the trie that returns all values for every
    /// `Leaf` and `Hash` node.
    fn values(&self) -> impl Iterator<Item = ValOrHash>;
}

pub(crate) trait TrieNodeIntern {
    fn hash_intern(&self) -> EncodedNode;
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
/// A partial trie, or a sub-trie thereof. This mimics the structure of an
/// Ethereum trie, except with an additional `Hash` node type, representing a
/// node whose data is not needed to process our transaction.
pub enum Node<T>
where
    T: Clone + Debug,
{
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
        children: [WrappedNode<T>; 16],
        value: Vec<u8>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        nibbles: Nibbles,
        child: WrappedNode<T>,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf { nibbles: Nibbles, value: Vec<u8> },
}

impl<N: PartialTrie> Eq for Node<N> {}

/// `PartialTrie` equality means all nodes through the trie are equivalent.
impl<N: PartialTrie> PartialEq for Node<N> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Node::Empty, Node::Empty) => true,
            (Node::Hash(h1), Node::Hash(h2)) => h1 == h2,
            (
                Node::Branch {
                    children: c1,
                    value: v1,
                },
                Node::Branch {
                    children: c2,
                    value: v2,
                },
            ) => v1 == v2 && (0..16).all(|i| c1[i] == c2[i]),
            (
                Node::Extension {
                    nibbles: n1,
                    child: c1,
                },
                Node::Extension {
                    nibbles: n2,
                    child: c2,
                },
            ) => n1 == n2 && c1 == c2,
            (
                Node::Leaf {
                    nibbles: n1,
                    value: v1,
                },
                Node::Leaf {
                    nibbles: n2,
                    value: v2,
                },
            ) => n1 == n2 && v1 == v2,
            (_, _) => false,
        }
    }
}

/// A simple PartialTrie with no hash caching.
/// Note that while you can *still* calculate the hashes for any given node, the
/// hashes are not cached and are recalculated each time.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StandardTrie(pub Node<StandardTrie>);

impl PartialTrie for StandardTrie {
    fn new(n: Node<Self>) -> Self {
        Self(n)
    }

    fn insert<K, V>(&mut self, k: K, v: V)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
    {
        self.0.insert(k, v);
    }

    fn extend<K, V, I>(&mut self, nodes: I)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.0.extend(nodes)
    }

    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<Nibbles>,
    {
        self.0.get(k)
    }

    fn delete<K>(&mut self, k: K) -> Option<Vec<u8>>
    where
        K: Into<Nibbles>,
    {
        self.0.delete(k)
    }

    fn hash(&self) -> H256 {
        hash_trie(self)
    }

    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.0.items()
    }

    fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.0.keys()
    }

    fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.0.values()
    }
}

impl TrieNodeIntern for StandardTrie {
    fn hash_intern(&self) -> EncodedNode {
        rlp_encode_and_hash_node(self)
    }
}

impl Deref for StandardTrie {
    type Target = Node<StandardTrie>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for StandardTrie {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> FromIterator<(K, V)> for StandardTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> Self {
        from_iter_common(nodes)
    }
}

/// A partial trie that lazily caches hashes for each node as needed.
/// If you are doing frequent hashing of node, you probably want to use this
/// `Trie` variant.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HashedPartialTrie {
    pub(crate) node: Node<HashedPartialTrie>,
    pub(crate) hash: Arc<RwLock<Option<H256>>>,
}

impl HashedPartialTrie {
    /// Lazily get calculates the hash for the node,
    pub fn get_hash(&self) -> H256 {
        let hash = *self.hash.read();

        match hash {
            Some(h) => h,
            None => self.hash(),
        }
    }

    pub(crate) fn set_hash(&self, _v: Option<H256>) {
        *self.hash.write() = None;
    }
}

impl PartialTrie for HashedPartialTrie {
    fn new(node: Node<Self>) -> Self {
        Self {
            node,
            hash: Arc::new(RwLock::new(None)),
        }
    }

    fn insert<K, V>(&mut self, k: K, v: V)
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
    {
        self.node.insert(k, v);
        self.set_hash(None);
    }

    fn extend<K, V, I>(&mut self, nodes: I)
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.node.extend(nodes);
        self.set_hash(None);
    }

    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        self.node.get(k)
    }

    fn delete<K>(&mut self, k: K) -> Option<Vec<u8>>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        let res = self.node.delete(k);
        self.set_hash(None);

        res
    }

    fn hash(&self) -> H256 {
        hash_trie(&self.node)
    }

    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.node.items()
    }

    fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.node.keys()
    }

    fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.node.values()
    }
}

impl TrieNodeIntern for HashedPartialTrie {
    fn hash_intern(&self) -> EncodedNode {
        if let Some(h) = *self.hash.read() {
            return EncodedNode::Hashed(h.0);
        }

        let res = rlp_encode_and_hash_node(&self.node);
        self.set_hash(Some((&res).into()));

        res
    }
}

impl Deref for HashedPartialTrie {
    type Target = Node<HashedPartialTrie>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl DerefMut for HashedPartialTrie {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl Eq for HashedPartialTrie {}
impl PartialEq for HashedPartialTrie {
    fn eq(&self, other: &Self) -> bool {
        self.node == other.node
    }
}

impl<K, V> FromIterator<(K, V)> for HashedPartialTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> Self {
        from_iter_common(nodes)
    }
}

fn from_iter_common<N: PartialTrie, T: IntoIterator<Item = (K, V)>, K, V>(nodes: T) -> N
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    let mut root = N::new(Node::Empty);
    root.extend(nodes.into_iter());

    root
}
