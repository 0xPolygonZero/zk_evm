use ethereum_types::{BigEndianHash, H256, U256};
use keccak_hash::keccak;

use crate::{smt::Smt, utils::u2b};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_smt: Smt,
    pub code_hash: H256,
}

impl Account {
    pub fn pack_u256(&self) -> Vec<U256> {
        vec![
            self.nonce.into(),
            self.balance,
            self.storage_smt.root.into_uint(),
            self.code_hash.into_uint(),
        ]
    }

    pub fn pack(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend(&self.nonce.to_be_bytes());
        v.extend(u2b(self.balance));
        v.extend(self.storage_smt.root.0);
        v.extend(self.code_hash.0);
        v
    }

    pub fn hash(&self) -> H256 {
        keccak(self.pack())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountWithStorageRoot {
    pub nonce: u64,
    pub balance: U256,
    pub storage_smt_root: H256,
    pub code_hash: H256,
}

impl AccountWithStorageRoot {
    pub fn pack(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend(&self.nonce.to_be_bytes());
        v.extend(u2b(self.balance));
        v.extend(self.storage_smt_root.0);
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

    use crate::smt::{AccountOrValue, Smt, ValOrHash};

    use super::Account;

    impl Distribution<Account> for Standard {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Account {
            Account {
                nonce: rng.gen(),
                balance: U256(rng.gen()),
                storage_smt: {
                    let n = 20;
                    let rand_node = |_| {
                        (
                            U256(rng.gen()).into(),
                            ValOrHash::Val(AccountOrValue::Value(U256(rng.gen()))),
                        )
                    };
                    Smt::new((0..n).map(rand_node)).unwrap()
                },
                code_hash: rng.gen(),
            }
        }
    }
}
