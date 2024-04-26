use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::{self, empty, once},
};

use ethereum_types::{Address, H256, U256, U512};
use log::trace;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    special_query::path_for_query,
    trie_ops::TrieOpError,
    trie_subsets::{create_trie_subset, SubsetTrieError},
    utils::{IntoTrieKey, TriePath, TrieSegment},
};
use thiserror::Error;

use crate::{
    aliased_crate_types::{
        MptAccountRlp, MptExtraBlockData, MptGenerationInputs, MptTrieInputs, MptTrieRoots,
    },
    decoding_mpt::{MptTraceParsingError, MptTraceParsingResult},
    decoding_traits::ProcessableBlockTrace,
    processed_block_trace::ProcessedBlockTrace,
    processed_block_trace_mpt::{NodesUsedByTxn, ProcessedSectionTxnInfo, StateTrieWrites},
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, HashedStorageAddrNibbles,
        OtherBlockData, TriePathIter, TrieRootHash, TxnIdx, EMPTY_ACCOUNT_BYTES_RLPED,
        ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, optional_field, optional_field_hex, update_val_if_some},
};

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
