use std::collections::HashMap;

use eth_trie_utils::partial_trie::HashedPartialTrie;
use plonky2_evm::generation::{GenerationInputs, TrieInputs};
use thiserror::Error;

use crate::{
    processed_block_trace::{
        BlockMetaState, NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo,
    },
    proof_gen_types::BlockLevelData,
    types::{Bloom, HashedAccountAddr},
};

pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

#[derive(Debug, Error)]
pub enum TraceParsingError {
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0})")]
    MissingAccountStorageTrie(HashedAccountAddr),

    // TODO: Make this error nicer...
    #[error(
        "Non-existent account addr given when creating a sub partial trie from the base state trie"
    )]
    NonExistentAcctAddrsCreatingSubPartialTrie,

    #[error("Creating a subset partial trie for account storage for account {0}, mem addrs accessed: {1:?}")]
    NonExistentStorageAddrsCreatingStorageSubPartialTrie(HashedAccountAddr, Vec<String>, String),
}

/// The current state of all tries as we process txn deltas. These are mutated
/// after every txn we process in the trace.
#[derive(Debug, Default)]
struct PartialTrieState {
    state: HashedPartialTrie,
    storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
    txn: HashedPartialTrie,
    receipt: HashedPartialTrie,
}

impl ProcessedBlockTrace {
    fn into_generation_inputs(self, b_data: BlockLevelData) -> Vec<GenerationInputs> {
        let mut trie_state = PartialTrieState::default();
        let mut b_meta_state = BlockMetaState::default();
        let mut txn_gen_inputs = Vec::with_capacity(self.txn_info.len());

        for (txn_idx, txn_info) in self.txn_info.into_iter().enumerate() {}

        txn_gen_inputs
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &PartialTrieState,
        nodes_used_by_txn: NodesUsedByTxn,
    ) -> TraceParsingResult<TrieInputs> {
        todo!()
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: Vec<ProcessedTxnInfo>,
        addrs_to_code: &mut HashMap<HashedAccountAddr, Vec<u8>>,
    ) -> TraceParsingResult<()> {
        todo!()
    }
}
