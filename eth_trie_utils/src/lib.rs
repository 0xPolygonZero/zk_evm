//! Utilities and types for working with Ethereum partial tries.

#![feature(slice_pattern)]

pub mod partial_trie;
pub mod trie_hashing;
pub mod trie_ops;
pub mod utils;

#[cfg(test)]
mod testing_utils;
