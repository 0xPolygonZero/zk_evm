use ethereum_types::H256;

use crate::types::CodeHash;

/// A trait for resolving code hashes into bytes.
pub trait CodeHashResolver {
    /// Resolves the code hash into bytes.
    fn resolve(&mut self, c_hash: &CodeHash) -> Vec<u8>;

    /// Inserts the code hash and its bytes into the resolver.
    fn insert_code(&mut self, c_hash: H256, code: Vec<u8>);
}
