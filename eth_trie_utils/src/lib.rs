#![feature(slice_pattern)]

pub mod partial_trie;
pub mod query;
pub mod trie_builder;
pub mod trie_hashing;
mod types;
mod utils;

#[cfg(test)]
mod testing_utils;
