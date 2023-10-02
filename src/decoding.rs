use std::collections::HashMap;

use eth_trie_utils::partial_trie::HashedPartialTrie;
use plonky2_evm::generation::GenerationInputs;

use crate::{
    processed_block_trace::{BlockMetaState, ProcessedBlockTrace},
    proof_gen_types::BlockLevelData,
    types::{Bloom, HashedAccountAddr},
};

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

        let txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, trace)| todo!())
            .collect();

        txn_gen_inputs
    }
}
