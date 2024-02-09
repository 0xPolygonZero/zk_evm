#![allow(clippy::needless_range_loop)]

use ethereum_types::U256;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::{Poseidon, PoseidonHash};
use plonky2::plonk::config::Hasher;

use crate::bits::Bits;
use crate::db::Db;
use crate::utils::{f2limbs, hash0, hash_key_hash, key2u, limbs2f, u2h, u2k};

// pub const RADIX: usize = 2;
// pub const DEFAULT_HASH: H256 = H256([0; 32]);

const HASH_TYPE: u8 = 0;
const INTERNAL_TYPE: u8 = 1;
const LEAF_TYPE: u8 = 2;

// pub type Error = String;

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum AccountOrValue {
//     Account(Account),
//     Value(U256),
// }

// impl From<Account> for AccountOrValue {
//     fn from(account: Account) -> Self {
//         Self::Account(account)
//     }
// }

// impl From<U256> for AccountOrValue {
//     fn from(value: U256) -> Self {
//         Self::Value(value)
//     }
// }

// impl AccountOrValue {
//     pub fn hash(&self) -> H256 {
//         match self {
//             AccountOrValue::Account(a) => a.hash(),
//             AccountOrValue::Value(v) => u2h(*v),
//         }
//     }
// }

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum ValOrHash {
//     Val(AccountOrValue),
//     Hash(H256),
// }

// impl From<Account> for ValOrHash {
//     fn from(account: Account) -> Self {
//         ValOrHash::Val(account.into())
//     }
// }

// impl<T: Into<U256>> From<T> for ValOrHash {
//     fn from(value: T) -> Self {
//         ValOrHash::Val((value.into()).into())
//     }
// }

// impl ValOrHash {
//     pub fn is_val(&self) -> bool {
//         matches!(self, ValOrHash::Val(_))
//     }

//     pub fn is_hash(&self) -> bool {
//         matches!(self, ValOrHash::Hash(_))
//     }

//     pub fn to_node(&self, rem_key: Bits) -> ValOrHashNode {
//         match self {
//             ValOrHash::Val(account) => ValOrHashNode::Val {
//                 rem_key,
//                 leaf: account.clone(),
//             },
//             ValOrHash::Hash(h) => ValOrHashNode::Hash(*h),
//         }
//     }
// }

// #[derive(Debug, PartialEq, Eq, Clone)]
// pub enum ValOrHashNode {
//     Val { rem_key: Bits, leaf: AccountOrValue },
//     Hash(H256),
// }

// impl ValOrHashNode {
//     pub fn is_val(&self) -> bool {
//         matches!(self, ValOrHashNode::Val { .. })
//     }

//     pub fn is_hash(&self) -> bool {
//         matches!(self, ValOrHashNode::Hash(_))
//     }

//     pub fn is_empty(&self) -> bool {
//         match self {
//             ValOrHashNode::Hash(h) => *h == DEFAULT_HASH,
//             _ => false,
//         }
//     }

//     pub fn hash(&self) -> H256 {
//         match self {
//             ValOrHashNode::Val { rem_key, leaf } => hash_leaf(*rem_key, leaf.hash()),
//             ValOrHashNode::Hash(h) => *h,
//         }
//     }
// }

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// pub struct InternalNode([H256; RADIX]);

// impl Default for InternalNode {
//     fn default() -> Self {
//         Self([DEFAULT_HASH; RADIX])
//     }
// }

// impl InternalNode {
//     pub fn hash(&self) -> H256 {
//         hash_internal(self.0)
//     }
// }

pub type F = GoldilocksField;
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Key(pub [F; 4]);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Node([F; 12]);
pub type Hash = PoseidonHash;
pub type HashOut = <PoseidonHash as Hasher<F>>::Hash;

impl Key {
    pub fn split(&self) -> Bits {
        let mut bits = Bits::empty();
        let mut arr: [_; 4] = std::array::from_fn(|i| self.0[i].to_canonical_u64());
        for _ in 0..64 {
            for j in 0..4 {
                bits.push_bit(arr[j] & 1 == 1);
                arr[j] >>= 1;
            }
        }
        bits
    }

    pub fn join(bits: Bits, rem_key: Self) -> Self {
        let mut n = [0; 4];
        let mut accs = [0; 4];
        for i in 0..bits.count {
            if bits.get_bit(i) {
                accs[i % 4] |= 1 << n[i % 4];
            }
            n[i % 4] += 1;
        }
        let key = std::array::from_fn(|i| {
            F::from_canonical_u64((rem_key.0[i].to_canonical_u64() << n[i]) | accs[i])
        });
        Key(key)
    }

    fn remove_key_bits(&self, nbits: usize) -> Self {
        let full_levels = nbits / 4;
        let mut auxk = self.0.map(|x| x.to_canonical_u64());
        for i in 0..4 {
            let mut n = full_levels;
            if full_levels * 4 + i < nbits {
                n += 1;
            }
            auxk[i] >>= n;
        }
        Key(auxk.map(F::from_canonical_u64))
    }
}

impl Node {
    pub fn is_one_siblings(&self) -> bool {
        self.0[8].is_one()
    }
}

/// Sparse Merkle tree (SMT).
/// Represented as a map from keys to leaves and a map from keys to internal nodes.
/// Leaves hold either a value node, representing an account in the state SMT or a value in the storage SMT,
/// or a hash node, representing a hash of a subtree.
/// Internal nodes hold the hashes of their children.
/// The root is the hash of the root internal node.
/// Leaves are hashed using a prefix of 0, internal nodes using a prefix of 1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Smt<D: Db> {
    pub db: D,
    pub root: HashOut,
}

impl<D: Db> Smt<D> {
    pub fn hash0(&mut self, x: [F; 8]) -> [F; 4] {
        let h = hash0(x);
        let a = std::array::from_fn(|i| {
            // (i < 8).then_some(x[i]).unwrap_or_default()
            if i < 8 {
                x[i]
            } else {
                F::ZERO
            }
        });
        self.db.set_node(Key(h), Node(a));
        h
    }

    pub fn hash_key_hash(&mut self, k: Key, h: [F; 4]) -> [F; 4] {
        let a: [_; 8] = std::array::from_fn(|i| if i < 4 { k.0[i] } else { h[i - 4] });
        let a = std::array::from_fn(|i| match i {
            j if j < 8 => a[i],
            8 => F::ONE,
            _ => F::ZERO,
        });
        let h = hash_key_hash(k, h);
        self.db.set_node(Key(h), Node(a));
        h
    }

    pub fn get(&self, key: Key) -> U256 {
        let keys = key.split();
        let mut level = 0;
        let mut acc_key = Bits::empty();
        let mut r = Key(self.root.elements);

        while !r.0.iter().all(F::is_zero) {
            let sibling = self.db.get_node(&r).unwrap();
            if sibling.is_one_siblings() {
                let found_val_a: [F; 8] = self
                    .db
                    .get_node(&Key(sibling.0[4..8].try_into().unwrap()))
                    .unwrap()
                    .0[0..8]
                    .try_into()
                    .unwrap();
                let found_rem_key = Key(sibling.0[0..4].try_into().unwrap());
                let found_val = limbs2f(found_val_a);
                let found_key = Key::join(acc_key, found_rem_key);
                if found_key == key {
                    return found_val;
                } else {
                    return U256::zero();
                }
            } else {
                let b = keys.get_bit(level as usize);
                r = Key(sibling.0[b as usize * 4..(b as usize + 1) * 4]
                    .try_into()
                    .unwrap());
                acc_key.push_bit(b);
                level += 1;
            }
        }
        unreachable!()
    }

    pub fn set(&mut self, key: Key, value: U256) {
        let mut r = Key(self.root.elements);
        let mut new_root = self.root;
        let keys = key.split();
        let mut level = 0isize;
        let mut acc_key = Bits::empty();
        let mut found_key = None;
        let mut found_rem_key = None;
        let mut found_old_val_h = None;
        let mut siblings = vec![];

        while !r.0.iter().all(F::is_zero) {
            let sibling = self.db.get_node(&r).unwrap();
            siblings.push(*sibling);
            if sibling.is_one_siblings() {
                found_old_val_h = Some(sibling.0[4..8].try_into().unwrap());
                let found_val_a: [F; 8] =
                    self.db.get_node(&Key(found_old_val_h.unwrap())).unwrap().0[0..8]
                        .try_into()
                        .unwrap();
                found_rem_key = Some(Key(sibling.0[0..4].try_into().unwrap()));
                let _found_val = limbs2f(found_val_a);
                found_key = Some(Key::join(acc_key, found_rem_key.unwrap()));
                break;
            } else {
                let b = keys.get_bit(level as usize);
                r = Key(sibling.0[b as usize * 4..(b as usize + 1) * 4]
                    .try_into()
                    .unwrap());
                acc_key.push_bit(b);
                level += 1;
            }
        }

        level -= 1;
        if !acc_key.is_empty() {
            acc_key.pop_next_bit();
        }

        if value.is_zero() {
            if let Some(found_key) = found_key {
                if key == found_key {
                    if level >= 0 {
                        let i = (keys.get_bit(level as usize) as usize) * 4;
                        siblings[level as usize].0[i..i + 4].copy_from_slice(&[F::ZERO; 4]);
                        let mut u_key = get_unique_sibling(siblings[level as usize]);

                        if u_key >= 0 {
                            let k = siblings[level as usize].0
                                [u_key as usize * 4..u_key as usize * 4 + 4]
                                .try_into()
                                .unwrap();
                            siblings[(level + 1) as usize] = *self.db.get_node(&Key(k)).unwrap();
                            if siblings[(level + 1) as usize].is_one_siblings() {
                                let val_h =
                                    siblings[(level + 1) as usize].0[4..8].try_into().unwrap();
                                let val_a = self.db.get_node(&Key(val_h)).unwrap().0[0..8]
                                    .try_into()
                                    .unwrap();
                                let r_key =
                                    siblings[(level + 1) as usize].0[0..4].try_into().unwrap();

                                let _val = limbs2f(val_a);

                                assert!(u_key == 0 || u_key == 1);
                                let ins_key = Key::join(acc_key.add_bit(u_key != 0), Key(r_key));
                                while (u_key >= 0) && (level >= 0) {
                                    level -= 1;
                                    if level >= 0 {
                                        u_key = get_unique_sibling(siblings[level as usize]);
                                    }
                                }

                                let old_key = ins_key.remove_key_bits((level + 1) as usize);
                                let old_leaf_hash = self.hash_key_hash(old_key, val_h);

                                if level >= 0 {
                                    let b = keys.get_bit(level as usize) as usize * 4;
                                    siblings[level as usize].0[b..b + 4]
                                        .copy_from_slice(&old_leaf_hash);
                                } else {
                                    new_root = HashOut {
                                        elements: old_leaf_hash,
                                    };
                                }
                            } else {
                                // panic!()
                            }
                        } else {
                            panic!()
                        }
                    } else {
                        new_root = HashOut {
                            elements: [F::ZERO; 4],
                        };
                    }
                }
            }
        } else if let Some(found_key) = found_key {
            if key == found_key {
                let new_val_h = self.hash0(f2limbs(value));
                let new_leaf_hash = self.hash_key_hash(found_rem_key.unwrap(), new_val_h);
                if level >= 0 {
                    let i = (keys.get_bit(level as usize) as usize) * 4;
                    siblings[level as usize].0[i..i + 4].copy_from_slice(&new_leaf_hash);
                } else {
                    new_root = HashOut {
                        elements: new_leaf_hash,
                    };
                }
            } else {
                let mut node = [F::ZERO; 8];
                let mut level2 = level + 1;
                let found_keys = found_key.split();
                while keys.get_bit(level2 as usize) == found_keys.get_bit(level2 as usize) {
                    level2 += 1;
                }
                let old_key = found_key.remove_key_bits(level2 as usize + 1);
                let old_leaf_hash = self.hash_key_hash(old_key, found_old_val_h.unwrap());

                let new_key = key.remove_key_bits(level2 as usize + 1);
                let new_val_h = self.hash0(f2limbs(value));
                let new_leaf_hash = self.hash_key_hash(new_key, new_val_h);

                let b = keys.get_bit(level2 as usize) as usize * 4;
                let bb = found_keys.get_bit(level2 as usize) as usize * 4;
                node[b..b + 4].copy_from_slice(&new_leaf_hash);
                node[bb..bb + 4].copy_from_slice(&old_leaf_hash);

                let mut r2 = self.hash0(node);
                level2 -= 1;

                while level2 != level {
                    node = [F::ZERO; 8];
                    let b = keys.get_bit(level2 as usize) as usize * 4;
                    node[b..b + 4].copy_from_slice(&r2);

                    r2 = self.hash0(node);
                    level2 -= 1;
                }

                if level >= 0 {
                    let b = keys.get_bit(level as usize) as usize * 4;
                    siblings[level as usize].0[b..b + 4].copy_from_slice(&r2);
                } else {
                    new_root = HashOut { elements: r2 };
                }
            }
        } else {
            let new_key = key.remove_key_bits((level + 1) as usize);
            let new_val_h = self.hash0(f2limbs(value));
            let new_leaf_hash = self.hash_key_hash(new_key, new_val_h);

            if level >= 0 {
                let b = keys.get_bit(level as usize) as usize * 4;
                siblings[level as usize].0[b..b + 4].copy_from_slice(&new_leaf_hash);
            } else {
                new_root = HashOut {
                    elements: new_leaf_hash,
                };
            }
        }
        siblings.truncate((level + 1) as usize);

        while level >= 0 {
            new_root = F::poseidon(siblings[level as usize].0)[0..4]
                .try_into()
                .unwrap();
            self.db
                .set_node(Key(new_root.elements), siblings[level as usize]);
            level -= 1;
            if level >= 0 {
                let b = keys.get_bit(level as usize) as usize * 4;
                siblings[level as usize].0[b..b + 4].copy_from_slice(&new_root.elements);
            }
        }
        self.root = new_root;
    }

    /// Serialize the SMT into a vector of U256.
    /// Starts with a [0, 0] for convenience, that way `ptr=0` is a canonical empty node.
    /// Therefore the root of the SMT is at `ptr=2`.
    /// Serialization rules:
    /// ```pseudocode
    /// serialize( HashNode { h } ) = [HASH_TYPE, h]
    /// serialize( InternalNode { left, right } ) = [INTERNAL_TYPE, serialize(left).ptr, serialize(right).ptr]
    /// serialize( LeafNode { key, value } ) = [LEAF_TYPE, serialize(key || value).ptr]
    /// ```
    pub fn serialize(&self) -> Vec<U256> {
        let mut v = vec![U256::zero(); 2]; // For empty hash node.
        let key = Key(self.root.elements);
        serialize(self, key, &mut v);
        if v.len() == 2 {
            v.extend([U256::zero(); 2]);
        }
        v
    }
}

// impl Default for Smt {
//     fn default() -> Self {
//         Self::empty()
//     }
// }

// impl Smt {
//     pub fn empty() -> Self {
//         Self {
//             leaves: BTreeMap::from_iter([(Bits::empty(), ValOrHashNode::Hash(DEFAULT_HASH))]),
//             internal_nodes: BTreeMap::new(),
//             root: DEFAULT_HASH,
//         }
//     }

//     pub fn new<I>(iter: I) -> Result<Self, Error>
//     where
//         I: IntoIterator<Item = (Bits, ValOrHash)>,
//     {
//         let mut smt = Self::empty();
//         for (key, value) in iter {
//             smt.insert(key, value)?;
//         }
//         Ok(smt)
//     }

//     pub fn is_empty(&self) -> bool {
//         let empty = self.root == DEFAULT_HASH;
//         if empty {
//             assert!(self.internal_nodes.is_empty());
//             assert_eq!(
//                 self.leaves,
//                 BTreeMap::from_iter([(Bits::empty(), ValOrHashNode::Hash(DEFAULT_HASH))])
//             );
//         }
//         empty
//     }

//     pub fn leaves<I>(self) -> Vec<(Bits, ValOrHash)> {
//         self.leaves
//             .into_iter()
//             .map(|(k, v)| match v {
//                 ValOrHashNode::Val { rem_key, leaf } => (k + rem_key, ValOrHash::Val(leaf)),
//                 ValOrHashNode::Hash(h) => (k, ValOrHash::Hash(h)),
//             })
//             .collect()
//     }

//     fn insert_helper(
//         &mut self,
//         current_key: Bits,
//         rem_key: Bits,
//         value: &ValOrHash,
//     ) -> Result<(), Error> {
//         if self.internal_nodes.contains_key(&current_key) {
//             let mut rem = rem_key;
//             let new_key = current_key.add_bit(rem.pop_next_bit());
//             return self.insert_helper(new_key, rem, value);
//         }
//         match self.leaves.get(&current_key) {
//             Some(ValOrHashNode::Hash(h)) if h.is_zero() => {
//                 self.leaves.insert(current_key, value.to_node(rem_key));
//                 self.update_hashes(current_key);
//             }
//             Some(ValOrHashNode::Val { rem_key: k, leaf }) => {
//                 let k = *k;
//                 let leaf = leaf.clone();
//                 if k == rem_key {
//                     return Err("Key already exists. Use update instead.".to_string());
//                 }
//                 self.internal_nodes
//                     .insert(current_key, InternalNode::default());
//                 self.leaves.remove(&current_key);
//                 self.insert_helper(current_key, k, &ValOrHash::Val(leaf))?;
//                 self.insert_helper(current_key, rem_key, value)?;
//             }
//             None => {
//                 self.leaves.insert(current_key, value.to_node(rem_key));
//                 self.update_hashes(current_key);
//             }
//             _ => panic!("Should not happen"),
//         }
//         Ok(())
//     }

//     pub fn insert(&mut self, key: Bits, value: ValOrHash) -> Result<(), Error> {
//         if value.is_val() && key.count != 256 {
//             return Err("Key must be 256 bits".to_string());
//         }
//         self.insert_helper(Bits::empty(), key, &value)
//     }

//     /// Serialize the SMT into a vector of U256.
//     /// Starts with a [0, 0] for convenience, that way `ptr=0` is a canonical empty node.
//     /// Therefore the root of the SMT is at `ptr=2`.
//     /// Serialization rules:
//     /// ```pseudocode
//     /// serialize( HashNode { h } ) = [HASH_TYPE, h]
//     /// serialize( InternalNode { left, right } ) = [INTERNAL_TYPE, serialize(left).ptr, serialize(right).ptr]
//     /// serialize( LeafNode { key, value } ) = [LEAF_TYPE, serialize(key || value).ptr]
//     /// ```
//     pub fn serialize(&self) -> Vec<U256> {
//         let mut v = vec![U256::zero(); 2]; // For empty hash node.
//         let key = Bits::empty();
//         serialize(self, key, &mut v);
//         v
//     }

//     /// Update the hashes in the SMT's internal nodes from `current_key` to the root.
//     fn update_hashes(&mut self, current_key: Bits) {
//         let leaf = self.leaves.get(&current_key).expect("Should exist");
//         let mut hash = leaf.hash();
//         let mut key = current_key;
//         loop {
//             if key.is_empty() {
//                 self.root = hash;
//                 return;
//             }
//             let bit = key.pop_next_bit();
//             let internal = self.internal_nodes.get_mut(&key).expect("Should exist");
//             internal.0[bit as usize] = hash;
//             hash = internal.hash();
//         }
//     }
// }

fn serialize<D: Db>(smt: &Smt<D>, key: Key, v: &mut Vec<U256>) -> usize {
    if key.0.iter().all(F::is_zero) {
        return 0; // `ptr=0` is an empty node.
    }

    if let Some(node) = smt.db.get_node(&key) {
        if node.0.iter().all(F::is_zero) {
            panic!("wtf?");
        }

        if node.is_one_siblings() {
            let val_h = node.0[4..8].try_into().unwrap();
            let val_a = smt.db.get_node(&Key(val_h)).unwrap().0[0..8]
                .try_into()
                .unwrap();
            let rem_key = Key(node.0[0..4].try_into().unwrap());
            let val = limbs2f(val_a);
            let index = v.len();
            v.push(LEAF_TYPE.into());
            v.push(key2u(rem_key));
            v.push(val);
            index
        } else {
            let key_left = Key(node.0[0..4].try_into().unwrap());
            let key_right = Key(node.0[4..8].try_into().unwrap());
            let index = v.len();
            v.push(INTERNAL_TYPE.into());
            v.push(U256::zero());
            v.push(U256::zero());
            let i_left = serialize(smt, key_left, v).into();
            v[index + 1] = i_left;
            let i_right = serialize(smt, key_right, v).into();
            v[index + 2] = i_right;
            index
        }
    } else {
        todo!("Add a hash node here.");
    }

    //     match node {
    //         ValOrHashNode::Val { rem_key, leaf } => {
    //             let index = v.len();
    //             v.push(LEAF_TYPE.into());
    //             v.push((index + 2).into());
    //             v.push(rem_key.packed);
    //             match leaf {
    //                 AccountOrValue::Account(account) => {
    //                     v.extend(account.pack_u256());
    //                     let storage_smt_index = v.len();
    //                     v[storage_smt_index - 2] =
    //                         serialize(&account.storage_smt, Bits::empty(), v).into();
    //                 }
    //                 AccountOrValue::Value(val) => {
    //                     v.push(*val);
    //                 }
    //             }
    //             index
    //         }
    //         ValOrHashNode::Hash(h) => {
    //             let index = v.len();
    //             v.push(HASH_TYPE.into());
    //             v.push(h.0.into());
    //             index
    //         }
    //     }
    // } else if smt.internal_nodes.contains_key(&key) {
    //     let index = v.len();
    //     v.push(INTERNAL_TYPE.into());
    //     for _ in 0..RADIX {
    //         v.push(U256::zero());
    //     }
    //     for b in 0..RADIX {
    //         let child_index = serialize(smt, key.add_bit(b == 1), v);
    //         v[1 + index + b] = child_index.into();
    //     }
    //     index
    // } else {
    //     // Empty node
    //     return 0; // `ptr=0` is an empty node.
    // }
}

/// Hash a serialized state SMT, i.e., one where leaves hold accounts.
pub fn hash_serialize(v: &[U256]) -> HashOut {
    _hash_serialize(v, 2)
}

// /// Hash a serialized storage SMT, i.e., one where leaves hold scalar values.
// pub fn hash_serialize_storage(v: &[U256]) -> H256 {
//     _hash_serialize(v, 2, true)
// }

fn _hash_serialize(v: &[U256], ptr: usize) -> HashOut {
    assert!(v[ptr] <= u8::MAX.into());
    match v[ptr].as_u64() as u8 {
        HASH_TYPE => u2h(v[ptr + 1]),

        INTERNAL_TYPE => {
            let mut node = Node([F::ZERO; 12]);
            for b in 0..2 {
                let child_index = v[ptr + 1 + b];
                let child_hash = _hash_serialize(v, child_index.as_usize());
                node.0[b * 4..(b + 1) * 4].copy_from_slice(&child_hash.elements);
            }
            F::poseidon(node.0)[0..4].try_into().unwrap()
        }
        LEAF_TYPE => {
            let rem_key = u2k(v[ptr + 1]);
            let value = f2limbs(v[ptr + 2]);
            dbg!(key2u(rem_key), v[ptr + 2]);
            let value_h = hash0(value);
            let mut node = Node([F::ZERO; 12]);
            node.0[8] = F::ONE;
            node.0[0..4].copy_from_slice(&rem_key.0);
            node.0[4..8].copy_from_slice(&value_h);
            F::poseidon(node.0)[0..4].try_into().unwrap()
        }
        _ => panic!("Should not happen"),
    }
}

// #[cfg(test)]
// mod tests {
//     use ethereum_types::U256;
//     use rand::{seq::SliceRandom, thread_rng, Rng};

//     use crate::{account::Account, smt::hash_serialize_state};

//     use super::Smt;

//     #[test]
//     fn test_small_smt() -> Result<(), String> {
//         let account0 = Account::rand(10);
//         let account1 = Account::rand(10);

//         let nodes = [
//             (U256::from(3).into(), account0.clone().into()),
//             (U256::one().into(), account1.clone().into()),
//         ];
//         let smt0 = Smt::new(nodes)?;
//         let v = smt0.serialize();
//         assert_eq!(hash_serialize_state(&v), smt0.root);

//         let nodes = [
//             (U256::one().into(), account1.into()),
//             (U256::from(3).into(), account0.into()),
//         ];
//         let smt1 = Smt::new(nodes)?;

//         assert_eq!(smt0, smt1);

//         Ok(())
//     }

//     #[test]
//     fn test_small_smt_bis() -> Result<(), String> {
//         let account0 = Account::rand(10);
//         let account1 = Account::rand(10);

//         let nodes = [
//             (
//                 U256::from_dec_str(
//                     "57896044618658097711785492504343953926634992332820282019728792003956564819968",
//                 )
//                 .unwrap()
//                 .into(),
//                 account0.clone().into(),
//             ),
//             (
//                 U256::from_dec_str(
//                     "86844066927987146567678238756515930889952488499230423029593188005934847229952",
//                 )
//                 .unwrap()
//                 .into(),
//                 account1.clone().into(),
//             ),
//         ];
//         let smt0 = Smt::new(nodes)?;
//         let v = smt0.serialize();
//         assert_eq!(hash_serialize_state(&v), smt0.root);

//         let nodes = [
//             (
//                 U256::from_dec_str(
//                     "86844066927987146567678238756515930889952488499230423029593188005934847229952",
//                 )
//                 .unwrap()
//                 .into(),
//                 account1.into(),
//             ),
//             (
//                 U256::from_dec_str(
//                     "57896044618658097711785492504343953926634992332820282019728792003956564819968",
//                 )
//                 .unwrap()
//                 .into(),
//                 account0.into(),
//             ),
//         ];
//         let smt1 = Smt::new(nodes)?;

//         assert_eq!(smt0, smt1);

//         Ok(())
//     }

//     #[test]
//     fn test_random_smt() -> Result<(), String> {
//         let n = 1000;
//         let mut rng = thread_rng();
//         let rand_node = |_| (U256(rng.gen()).into(), Account::rand(10).into());
//         let mut rand_nodes = (0..n).map(rand_node).collect::<Vec<_>>();
//         let smt0 = Smt::new(rand_nodes.iter().cloned())?;
//         let v = smt0.serialize();
//         assert_eq!(hash_serialize_state(&v), smt0.root);

//         rand_nodes.shuffle(&mut rng);
//         let smt1 = Smt::new(rand_nodes)?;

//         assert_eq!(smt0, smt1);

//         Ok(())
//     }
// }

fn get_unique_sibling(node: Node) -> isize {
    let mut nfound = 0;
    let mut fnd = 0;
    for i in (0..12).step_by(4) {
        if !(node.0[i].is_zero()
            && node.0[i + 1].is_zero()
            && node.0[i + 2].is_zero()
            && node.0[i + 3].is_zero())
        {
            nfound += 1;
            fnd = i as isize / 4;
        }
    }
    if nfound == 1 {
        fnd
    } else {
        -1
    }
}
