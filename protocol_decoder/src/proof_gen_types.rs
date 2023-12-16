use std::borrow::Borrow;

use ethereum_types::U256;
use plonky2_evm::proof::ExtraBlockData;
use serde::{Deserialize, Serialize};

use crate::types::{TrieRootHash, TxnIdx};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProofBeforeAndAfterDeltas {
    pub gas_used_before: U256,
    pub gas_used_after: U256,
}

impl<T: Borrow<ExtraBlockData>> From<T> for ProofBeforeAndAfterDeltas {
    fn from(v: T) -> Self {
        let b = v.borrow();

        Self {
            gas_used_before: b.gas_used_before,
            gas_used_after: b.gas_used_after,
        }
    }
}

impl ProofBeforeAndAfterDeltas {
    pub fn into_extra_block_data(
        self,
        checkpoint_state_trie_root: TrieRootHash,
        txn_start: TxnIdx,
        txn_end: TxnIdx,
    ) -> ExtraBlockData {
        ExtraBlockData {
            checkpoint_state_trie_root,
            txn_number_before: txn_start.into(),
            txn_number_after: txn_end.into(),
            gas_used_before: self.gas_used_before,
            gas_used_after: self.gas_used_after,
        }
    }
}
