use eth_trie_utils::nibbles::Nibbles;
use ethereum_types::{H256, U256};
use plonky2_evm::proof::{BlockHashes, BlockMetadata};
use serde::{Deserialize, Serialize};

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
