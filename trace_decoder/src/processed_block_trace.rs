use ethereum_types::{Address, U256};

use crate::compact::compact_to_mpt_trie::StateTrieExtractionOutput;

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace<T> {
    pub(crate) spec: T,
    pub(crate) withdrawals: Vec<(Address, U256)>,
}
