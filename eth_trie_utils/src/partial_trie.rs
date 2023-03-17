//! Definitions for the core types [`PartialTrie`] and [`Nibbles`].

use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use ethereum_types::H256;
use serde::{Deserialize, Serialize};

use crate::{nibbles::Nibbles, trie_ops::ValOrHash};

/// Alias for a node that is a child of an extension or branch node.
pub type WrappedNode<N> = Arc<Box<N>>;

impl<N: TrieNode> AsRef<Node<N>> for WrappedNode<N> {
    fn as_ref(&self) -> &Node<N> {
        self
    }
}

impl<N: TrieNode> From<Node<N>> for WrappedNode<N> {
    fn from(v: Node<N>) -> Self {
        Arc::new(Box::new(N::new(v)))
    }
}

pub trait TrieNode:
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

    fn insert<K, V>(&mut self, k: K, v: V)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>;

    fn extend<K, V, I>(&mut self, nodes: I)
    where
        K: Into<Nibbles>,
        V: Into<ValOrHash>,
        I: IntoIterator<Item = (K, V)>;

    fn get<K>(&self, k: K) -> Option<&[u8]>
    where
        K: Into<Nibbles>;

    fn delete<K>(&mut self, k: K) -> Option<Vec<u8>>
    where
        K: Into<Nibbles>;

    fn items(&self) -> impl Iterator<Item = (Nibbles, ValOrHash)>;
    fn keys(&self) -> impl Iterator<Item = Nibbles>;
    fn values(&self) -> impl Iterator<Item = ValOrHash>;
}

#[derive(Clone, Debug)]
/// A partial trie, or a sub-trie thereof. This mimics the structure of an
/// Ethereum trie, except with an additional `Hash` node type, representing a
/// node whose data is not needed to process our transaction.
pub enum Node<T>
where
    T: TrieNode + Clone + Debug,
{
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

impl<'de, N: Deserialize<'de> + TrieNode> Deserialize<'de> for Node<N> {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}

impl<N: Serialize + TrieNode> Serialize for Node<N> {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        todo!()
    }
}

impl<N: TrieNode> Eq for Node<N> {}

/// `PartialTrie` equality means all nodes through the trie are equivalent.
impl<N: TrieNode> PartialEq for Node<N> {
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

impl<N: TrieNode> Default for Node<N> {
    fn default() -> Self {
        Self::Empty
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartialTrie(pub Node<PartialTrie>);

impl TrieNode for PartialTrie {
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

impl Deref for PartialTrie {
    type Target = Node<PartialTrie>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PartialTrie {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K, V> FromIterator<(K, V)> for PartialTrie
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(nodes: T) -> Self {
        from_iter_common(nodes)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HashedPartialTrie {
    node: Node<HashedPartialTrie>,
    hash: Option<H256>,
}

impl TrieNode for HashedPartialTrie {
    fn new(node: Node<Self>) -> Self {
        Self { node, hash: None }
    }

    fn insert<K, V>(&mut self, k: K, v: V)
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
    {
        self.node.insert(k, v);
        self.hash = None;
    }

    fn extend<K, V, I>(&mut self, nodes: I)
    where
        K: Into<crate::nibbles::Nibbles>,
        V: Into<crate::trie_ops::ValOrHash>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.node.extend(nodes);
        self.hash = None;
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
        self.hash = None;

        res
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

impl Deref for HashedPartialTrie {
    type Target = Node<HashedPartialTrie>;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}

impl DerefMut for HashedPartialTrie {
    fn deref_mut(&mut self) -> &mut Self::Target {
        todo!()
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

fn from_iter_common<N: TrieNode, T: IntoIterator<Item = (K, V)>, K, V>(nodes: T) -> N
where
    K: Into<Nibbles>,
    V: Into<ValOrHash>,
{
    let mut root = N::new(Node::Empty);
    root.extend(nodes.into_iter());

    root
}
