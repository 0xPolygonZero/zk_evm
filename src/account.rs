// use ::rand::{thread_rng, Rng};
// use ethereum_types::{BigEndianHash, H256, U256};
// use keccak_hash::keccak;

// use crate::{
//     smt::{AccountOrValue, Smt, ValOrHash},
//     utils::u2b,
// };

// // #[derive(Debug, Clone, PartialEq, Eq)]
// // pub struct Account {
// //     pub nonce: u64,
// //     pub balance: U256,
// //     pub storage_smt: Smt,
// //     pub code_hash: H256,
// // }

// // impl Default for Account {
// //     fn default() -> Self {
// //         Self {
// //             nonce: Default::default(),
// //             balance: Default::default(),
// //             storage_smt: Default::default(),
// //             code_hash: keccak([]),
// //         }
// //     }
// // }

// // impl Account {
// //     pub fn pack_u256(&self) -> Vec<U256> {
// //         vec![
// //             self.nonce.into(),
// //             self.balance,
// //             self.storage_smt.root.into_uint(),
// //             self.code_hash.into_uint(),
// //         ]
// //     }

// //     pub fn pack(&self) -> Vec<u8> {
// //         let mut v = vec![];
// //         v.extend(&self.nonce.to_le_bytes());
// //         v.extend(u2b(self.balance));
// //         v.extend(self.storage_smt.root.0);
// //         v.extend(self.code_hash.0);
// //         v
// //     }

// //     pub fn hash(&self) -> H256 {
// //         keccak(self.pack())
// //     }

// //     pub fn rand(num_storage_slots: usize) -> Self {
// //         let mut rng = thread_rng();
// //         Account {
// //             nonce: rng.gen(),
// //             balance: U256(rng.gen()),
// //             storage_smt: {
// //                 let rand_node = |_| {
// //                     (
// //                         U256(rng.gen()).into(),
// //                         ValOrHash::Val(AccountOrValue::Value(U256(rng.gen()))),
// //                     )
// //                 };
// //                 Smt::new((0..num_storage_slots).map(rand_node)).unwrap()
// //             },
// //             code_hash: rng.gen(),
// //         }
// //     }
// // }

// // #[derive(Debug, Clone, PartialEq, Eq)]
// // pub struct AccountWithStorageRoot {
// //     pub nonce: u64,
// //     pub balance: U256,
// //     pub storage_smt_root: H256,
// //     pub code_hash: H256,
// // }

// // impl AccountWithStorageRoot {
// //     pub fn pack(&self) -> Vec<u8> {
// //         let mut v = vec![];
// //         v.extend(&self.nonce.to_le_bytes());
// //         v.extend(u2b(self.balance));
// //         v.extend(self.storage_smt_root.0);
// //         v.extend(self.code_hash.0);
// //         v
// //     }

// //     pub fn hash(&self) -> H256 {
// //         keccak(self.pack())
// //     }
// // }
