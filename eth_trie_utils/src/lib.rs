//! Utilities and types for working with Ethereum partial tries.

#![feature(let_chains)]

pub mod partial_trie;
mod trie_hashing;
pub mod trie_ops;
mod utils;

#[cfg(test)]
mod testing_utils;
