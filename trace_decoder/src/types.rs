use ethereum_types::{Address, H256, U256};
use evm_arithmetization::{
    generation::GenerationInputs,
    proof::{BlockHashes, BlockMetadata},
};
use mpt_trie::nibbles::Nibbles;
use serde::{Deserialize, Serialize};

/// A block height's type.
pub type BlockHeight = u64;
/// A bloom filter's type.
pub type Bloom = [U256; 8];
/// A code hash's type.
pub type CodeHash = H256;
/// The type of an account address's hash.
pub type HashedAccountAddr = H256;
/// The type of a node address's hash.
pub type HashedNodeAddr = H256;
/// The type of a storage address's hash.
pub type HashedStorageAddr = H256;
/// The type of a hashed storage address"s nibbles.
pub type HashedStorageAddrNibbles = Nibbles;
/// The type of a storage address.
pub type StorageAddr = H256;
/// The type of a storage address's nibbles.
pub type StorageAddrNibbles = H256;
/// A storage value's type.
pub type StorageVal = U256;
/// A trie root hash's type.
pub type TrieRootHash = H256;
/// Type of a transaction's index within a block.
pub type TxnIdx = usize;

/// A function which turns a code hash into bytes.
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
pub type TxnProofGenIR = GenerationInputs;

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: TrieRootHash,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(Address, U256)>,
}
