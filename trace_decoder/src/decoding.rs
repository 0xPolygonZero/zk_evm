use std::fmt::{self, Display, Formatter};

/// An enum to cover all Ethereum trie types (see https://ethereum.github.io/yellowpaper/paper.pdf for details).
#[derive(Clone, Copy, Debug)]
pub enum TrieType {
    /// State trie.
    State,
    /// Storage trie.
    Storage,
    /// Receipt trie.
    Receipt,
    /// Transaction trie.
    Txn,
}

impl Display for TrieType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TrieType::State => write!(f, "state"),
            TrieType::Storage => write!(f, "storage"),
            TrieType::Receipt => write!(f, "receipt"),
            TrieType::Txn => write!(f, "transaction"),
        }
    }
}
