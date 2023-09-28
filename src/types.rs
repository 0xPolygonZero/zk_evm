use ethereum_types::{H256, U256};

pub type BlockHeight = u64;
pub type Bloom = [U256; 8];
pub type CodeHash = H256;
pub type HashedAccountAddress = H256;
pub type StorageAddr = H256;
pub type StorageVal = U256;
pub type TxnIdx = usize;
