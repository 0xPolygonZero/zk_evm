use ethereum_types::H256;

// TODO: Change this
pub fn hash_bytes(bytes: &[u8]) -> H256 {
    let mut v = [0u8; 32];
    v[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    v[31] = 1;
    H256(v)
}
