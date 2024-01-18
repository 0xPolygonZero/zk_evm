//! Utilities and types for working with Ethereum partial tries.
//!
//! While there are other Ethereum trie libraries (such as [eth_trie](https://docs.rs/eth_trie/0.1.0/eth_trie), these libraries are not a good fit if:
//! - You only need a portion of an existing larger trie.
//! - You need this partial trie to produce the same hash as the full trie.
//!
//! The core of this library is the [`PartialTrie`][partial_trie::PartialTrie]
//! type, which represents a trie that is a subset of an existing larger one.
//! Nodes that are not to be included in the `PartialTrie` are replaced with
//! [`Hash`][partial_trie::Node::Hash] nodes, which contains the merkle
//! hash of the node it replaces.

#![allow(incomplete_features)]

pub mod debug_tools;
pub mod nibbles;
pub mod partial_trie;
mod trie_hashing;
pub mod trie_ops;
pub mod trie_subsets;
mod utils;

#[cfg(test)]
mod testing_utils;
