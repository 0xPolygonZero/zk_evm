//! Utilities and types for working with Ethereum partial tries.
//!
//! While there are other Ethereum trie libraries (such as [eth_trie](https://docs.rs/eth_trie/0.1.0/eth_trie)),
//! these libraries are not a good fit if:
//! - You only need a portion of an existing larger trie.
//! - You need this partial trie to produce the same hash as the full trie.
//!
//! The core of this library is the [`PartialTrie`][partial_trie::PartialTrie]
//! type, which represents a trie that is a subset of an existing larger one.
//! Nodes that are not to be included in the `PartialTrie` are replaced with
//! [`Hash`][partial_trie::Node::Hash] nodes, which contains the merkle
//! hash of the node it replaces.

#![allow(incomplete_features)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

pub mod builder;
pub mod nibbles;
pub mod partial_trie;
pub mod special_query;
mod trie_hashing;
pub mod trie_ops;
pub mod trie_subsets;
pub mod utils;

#[cfg(feature = "trie_debug")]
pub mod debug_tools;

#[cfg(test)]
pub(crate) mod testing_utils;
