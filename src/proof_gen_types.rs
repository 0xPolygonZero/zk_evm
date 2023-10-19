use std::borrow::Borrow;

use ethereum_types::U256;
use plonky2_evm::proof::ExtraBlockData;
use serde::{Deserialize, Serialize};

use crate::types::{TrieRootHash, TxnIdx};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProofBeforeAndAfterDeltas {
    pub gas_used_before: U256,
    pub gas_used_after: U256,
    pub block_bloom_before: [U256; 8],
    pub block_bloom_after: [U256; 8],
}

impl<T: Borrow<ExtraBlockData>> From<T> for ProofBeforeAndAfterDeltas {
    fn from(v: T) -> Self {
        let b = v.borrow();

        Self {
            gas_used_before: b.gas_used_before,
            gas_used_after: b.gas_used_after,
            block_bloom_before: b.block_bloom_before,
            block_bloom_after: b.block_bloom_after,
        }
    }
}

impl ProofBeforeAndAfterDeltas {
    pub fn into_extra_block_data(
        self,
        genesis_state_trie_root: TrieRootHash,
        txn_start: TxnIdx,
        txn_end: TxnIdx,
    ) -> ExtraBlockData {
        ExtraBlockData {
            genesis_state_trie_root,
            txn_number_before: txn_start.into(),
            txn_number_after: txn_end.into(),
            gas_used_before: self.gas_used_before,
            gas_used_after: self.gas_used_after,
            block_bloom_before: self.block_bloom_before,
            block_bloom_after: self.block_bloom_after,
        }
    }
}
