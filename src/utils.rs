use ethereum_types::H256;
use keccak_hash::keccak;

pub(crate) fn hash(bytes: &[u8]) -> H256 {
    H256::from(keccak(bytes).0)
}
