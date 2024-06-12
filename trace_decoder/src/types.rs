use ethereum_types::{H256, U256};
use mpt_trie_type_1::nibbles::Nibbles;

/// A type alias for [`H256`] of a code hash.
pub type CodeHash = H256;
/// A type alias for [`H256`] of an account address's hash.
pub type HashedAccountAddr = H256;
/// A type alias for [`H256`] of a node address's hash.
pub type HashedNodeAddr = H256;
/// A type alias for [`H256`] of a storage address's hash.
pub type HashedStorageAddr = H256;
/// A type alias for [`Nibbles`] of a hashed storage address's nibbles.
pub type HashedStorageAddrNibbles = Nibbles;
/// A type alias for [`H256`] of a storage address.
pub type StorageAddr = H256;
/// A type alias for [`U256`] of a storage value.
pub type StorageVal = U256;
/// A type alias for [`H256`] of a trie root hash.
pub type TrieRootHash = H256;
/// A type alias for [`usize`] of a transaction's index within a block.
pub type TxnIdx = usize;

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
