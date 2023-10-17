use ethereum_types::{BigEndianHash, H256, U256};
use keccak_hash::keccak;

use crate::utils::u2b;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}

impl Account {
    pub fn pack_u256(&self) -> Vec<U256> {
        vec![
            self.nonce.into(),
            self.balance,
            self.storage_root.into_uint(),
            self.code_hash.into_uint(),
        ]
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend(&self.nonce.to_be_bytes());
        v.extend(u2b(self.balance));
        v.extend(self.storage_root.0);
        v.extend(self.code_hash.0);
        v
    }

    pub fn hash(&self) -> H256 {
        keccak(self.pack())
    }
}

#[cfg(test)]
pub(crate) mod rand {
    use ethereum_types::U256;
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    use super::Account;

    impl Distribution<Account> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Account {
            Account {
                nonce: rng.gen(),
                balance: U256(rng.gen()),
                storage_root: rng.gen(),
                code_hash: rng.gen(),
            }
        }
    }
}
