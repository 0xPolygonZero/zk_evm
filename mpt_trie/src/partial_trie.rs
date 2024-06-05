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

macro_rules! impl_from_for_trie_type {
    ($type:ty) => {
        impl From<Node<$type>> for $type {
            fn from(v: Node<$type>) -> Self {
                Self::new(v)
            }
        }
    };
}

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

/// A trait for any types that are Tries.
pub trait PartialTrie:
    Clone + Debug + Default + DerefMut<Target = Node<Self>> + Eq + TrieNodeIntern
{
    /// Creates a new partial trie from a node.
    fn new(n: Node<Self>) -> Self;

    /// Inserts a node into the trie.
    fn insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>;

    /// Add more nodes to the trie through an iterator
    fn extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
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
    fn delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
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

    /// Returns `true` if the trie contains an element with the given key.
    fn contains<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>;
}

/// Part of the trait that is not really part of the public interface but
/// implementor of other node types still need to implement.
pub trait TrieNodeIntern {
    /// Returns the hash of the rlp encoding of self.
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
        /// A slice containing the 16 children of this branch node.
        children: [WrappedNode<T>; 16],
        /// The payload of this node.
        value: Vec<u8>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        /// The path of this extension.
        nibbles: Nibbles,
        /// The child of this extension node.
        child: WrappedNode<T>,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf {
        /// The path of this leaf node.
        nibbles: Nibbles,
        /// The payload of this node
        value: Vec<u8>,
    },
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

impl_from_for_trie_type!(StandardTrie);

impl PartialTrie for StandardTrie {
    fn new(n: Node<Self>) -> Self {
        Self(n)
    }

    fn insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
    {
        self.0.trie_insert(k, v)?;
        Ok(())
    }

    fn extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.0.trie_extend(nodes)
    }

    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<Nibbles>,
    {
        self.0.trie_get(k)
    }

    fn delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
    where
        K: Into<Nibbles>,
    {
        self.0.trie_delete(k)
    }

    fn hash(&self) -> H256 {
        hash_trie(self)
    }

    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.0.trie_items()
    }

    fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.0.trie_keys()
    }

    fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.0.trie_values()
    }

    fn contains<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>,
    {
        self.0.trie_has_item_by_key(k)
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

impl<K, V> TryFromIterator<(K, V)> for StandardTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn try_from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> TrieOpResult<Self> {
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

impl_from_for_trie_type!(HashedPartialTrie);

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

impl PartialTrie for HashedPartialTrie {
    fn new(node: Node<Self>) -> Self {
        Self {
            node,
            hash: Arc::new(RwLock::new(None)),
        }
    }

    fn insert<K, V>(&mut self, k: K, v: V) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
    {
        self.node.trie_insert(k, v)?;
        self.set_hash(None);
        Ok(())
    }

    fn extend<K, V, I>(&mut self, nodes: I) -> TrieOpResult<()>
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.node.trie_extend(nodes)?;
        self.set_hash(None);
        Ok(())
    }

    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        self.node.trie_get(k)
    }

    fn delete<K>(&mut self, k: K) -> TrieOpResult<Option<Vec<u8>>>
    where
        K: Into<crate::nibbles::Nibbles>,
    {
        let res = self.node.trie_delete(k);
        self.set_hash(None);

        res
    }

    fn hash(&self) -> H256 {
        self.get_hash()
    }

    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)> {
        self.node.trie_items()
    }

    fn keys(&self) -> impl Iterator<Item = Nibbles> {
        self.node.trie_keys()
    }

    fn values(&self) -> impl Iterator<Item = ValOrHash> {
        self.node.trie_values()
    }

    fn contains<K>(&self, k: K) -> bool
    where
        K: Into<Nibbles>,
    {
        self.node.trie_has_item_by_key(k)
    }
}

impl TrieNodeIntern for HashedPartialTrie {
    fn hash_intern(&self) -> EncodedNode {
        if let Some(h) = *self.hash.read() {
            return EncodedNode::Hashed(h.0);
        }

        let res = rlp_encode_and_hash_node(&self.node);
        // We can't hash anything smaller than 32 bytes (which is the case if it's a
        // `Raw` variant), so only cache if this isn't the case.
        if let EncodedNode::Hashed(h) = res {
            self.set_hash(Some(bytes_to_h256(&h)));
        }

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

impl<K, V> TryFromIterator<(K, V)> for HashedPartialTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn try_from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> TrieOpResult<Self> {
        from_iter_common(nodes)
    }
}

fn from_iter_common<N: PartialTrie, T: IntoIterator<Item = (K, V)>, K, V>(
    nodes: T,
) -> TrieOpResult<N>
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    let mut root = N::new(Node::Empty);
    root.extend(nodes)?;
    Ok(root)
}
