use eth_trie_utils::nibbles::Nibbles;
use ethereum_types::{H256, U256};
use plonky2_evm::{
    generation::GenerationInputs,
    proof::{BlockHashes, BlockMetadata, TrieRoots},
};
use serde::{Deserialize, Serialize};

use crate::proof_gen_types::ProofBeforeAndAfterDeltas;

pub type BlockHeight = u64;
pub type Bloom = [U256; 8];
pub type CodeHash = H256;
pub type HashedAccountAddr = H256;
pub type HashedNodeAddr = H256;
pub type HashedStorageAddr = H256;
pub type HashedStorageAddrNibbles = Nibbles;
pub type StorageAddr = H256;
pub type StorageVal = U256;
pub type TrieRootHash = H256;
pub type TxnIdx = usize;

pub trait CodeHashResolveFunc = Fn(&CodeHash) -> Vec<u8>;

/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

/// An `IR` (Intermediate Representation) for a given txn in a block that we can
/// use to generate a proof for that txn.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnProofGenIR {
    pub txn_idx: TxnIdx,
    pub gen_inputs: GenerationInputs,
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    pub b_data: BlockLevelData,
    pub genesis_state_trie_root: TrieRootHash,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    pub b_meta: BlockMetadata,
    pub b_hashes: BlockHashes,
}
impl TxnProofGenIR {
    pub fn b_height(&self) -> BlockHeight {
        self.gen_inputs.block_metadata.block_number.as_u64()
    }

    pub fn txn_idx(&self) -> TxnIdx {
        self.txn_idx
    }

    pub fn deltas(&self) -> ProofBeforeAndAfterDeltas {
        ProofBeforeAndAfterDeltas {
            gas_used_before: self.gen_inputs.gas_used_before,
            gas_used_after: self.gen_inputs.gas_used_after,
            block_bloom_before: self.gen_inputs.block_bloom_before,
            block_bloom_after: self.gen_inputs.block_bloom_after,
        }
    }

    /// Creates a dummy transaction.
    ///
    /// These can be used to pad a block if the number of transactions in the
    /// block is below `2`.
    pub fn create_dummy(b_height: BlockHeight, txn_idx: TxnIdx) -> Self {
        let trie_roots_after = TrieRoots {
            state_root: EMPTY_TRIE_HASH,
            transactions_root: EMPTY_TRIE_HASH,
            receipts_root: EMPTY_TRIE_HASH,
        };

        let block_metadata = BlockMetadata {
            block_number: b_height.into(),
            ..Default::default()
        };

        let gen_inputs = GenerationInputs {
            trie_roots_after,
            block_metadata,
            ..Default::default()
        };

        Self {
            txn_idx,
            gen_inputs,
        }
    }

    /// Copy relevant fields of the `TxnProofGenIR` to a new `TxnProofGenIR`
    /// with a different `b_height` and `txn_idx`.
    ///
    /// This can be used to pad a block if there is only one transaction in the
    /// block. Block proofs need a minimum of two transactions.
    pub fn dummy_with_at(&self, b_height: BlockHeight, txn_idx: TxnIdx) -> Self {
        let mut dummy = Self::create_dummy(b_height, txn_idx);

        dummy.gen_inputs.gas_used_before = self.gen_inputs.gas_used_after;
        dummy.gen_inputs.gas_used_after = self.gen_inputs.gas_used_after;
        dummy.gen_inputs.block_bloom_before = self.gen_inputs.block_bloom_after;
        dummy.gen_inputs.block_bloom_after = self.gen_inputs.block_bloom_after;

        dummy.gen_inputs.trie_roots_after = self.gen_inputs.trie_roots_after.clone();
        dummy
    }
}
