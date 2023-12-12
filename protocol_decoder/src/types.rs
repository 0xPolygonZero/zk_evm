use eth_trie_utils::nibbles::Nibbles;
use ethereum_types::{H256, U256};
use plonky2_evm::{
    generation::GenerationInputs,
    proof::{BlockHashes, BlockMetadata},
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
pub type StorageAddrNibbles = H256;
pub type StorageVal = U256;
pub type TrieRootHash = H256;
pub type TxnIdx = usize;

pub trait CodeHashResolveFunc = Fn(&CodeHash) -> Vec<u8>;

// 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
pub(crate) const EMPTY_CODE_HASH: H256 = H256([
    197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202,
    130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
]);

/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub(crate) const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

pub(crate) const EMPTY_ACCOUNT_BYTES_RLPED: [u8; 70] = [
    248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248,
    110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70,
    1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59,
    123, 250, 216, 4, 93, 133, 164, 112,
];

// This is just `rlp(0)`.
pub(crate) const ZERO_STORAGE_SLOT_VAL_RLPED: [u8; 1] = [128];

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
        }
    }
}
