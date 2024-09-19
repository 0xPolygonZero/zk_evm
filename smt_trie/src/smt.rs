#![allow(clippy::needless_range_loop)]

use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};

use ethereum_types::U256;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::{Poseidon, PoseidonHash};
use plonky2::plonk::config::Hasher;
use serde::{Deserialize, Serialize};

use crate::bits::Bits;
use crate::db::Db;
use crate::utils::{
    f2limbs, get_unique_sibling, hash0, hash_key_hash, hashout2u, key2u, limbs2f, u2h, u2k,
};

pub(crate) const HASH_TYPE: u8 = 0;
pub(crate) const INTERNAL_TYPE: u8 = 1;
pub(crate) const LEAF_TYPE: u8 = 2;

pub type F = GoldilocksField;
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Key(pub [F; 4]);
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node(pub [F; 12]);
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
/// Represented as a map from keys to leaves and a map from keys to internal
/// nodes. Leaves hold either a value node, representing an account in the state
/// SMT or a value in the storage SMT, or a hash node, representing a hash of a
/// subtree. Internal nodes hold the hashes of their children.
/// The root is the hash of the root internal node.
/// Leaves are hashed using a prefix of 0, internal nodes using a prefix of 1.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Smt<D: Db> {
    pub db: D,
    pub kv_store: HashMap<Key, U256>,
    pub root: HashOut,
}

impl<D: Db> Smt<D> {
    /// Returns `Poseidon(x, [0,0,0,0])` and save it in DB.
    pub fn hash0(&mut self, x: [F; 8]) -> [F; 4] {
        let h = hash0(x);
        let a = std::array::from_fn(|i| if i < 8 { x[i] } else { F::ZERO });
        self.db.set_node(Key(h), Node(a));
        h
    }

    /// Returns `Poseidon(key || h, [1,0,0,0])` and save it in DB.
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

    /// Returns the value associated with the key if it is in the SMT, otherwise
    /// returns 0.
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
                return if found_key == key {
                    assert_eq!(
                        found_val,
                        self.kv_store.get(&key).copied().unwrap_or_default()
                    );
                    found_val
                } else {
                    assert!(self
                        .kv_store
                        .get(&key)
                        .copied()
                        .unwrap_or_default()
                        .is_zero());
                    U256::zero()
                };
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

    /// Set the value associated with the key in the SMT.
    /// If the value is 0 and the key is in the SMT, the key is removed from the
    /// SMT. Reference implementation in https://github.com/0xPolygonHermez/zkevm-commonjs/blob/main/src/smt.js.
    pub fn set(&mut self, key: Key, value: U256) {
        if value.is_zero() {
            self.kv_store.remove(&key);
        } else {
            self.kv_store.insert(key, value);
        }
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

    /// Delete the key in the SMT.
    pub fn delete(&mut self, key: Key) {
        self.kv_store.remove(&key);
        self.set(key, U256::zero());
    }

    /// Set the key to the hash in the SMT.
    /// Needs to be called before any call to `set` to avoid issues.
    pub fn set_hash(&mut self, key: Bits, hash: HashOut) {
        let mut r = Key(self.root.elements);
        let mut new_root = self.root;
        let mut level = 0isize;
        let mut siblings = vec![];

        for _ in 0..key.count {
            let sibling = self.db.get_node(&r).unwrap_or(&Node([F::ZERO; 12]));
            siblings.push(*sibling);
            if sibling.is_one_siblings() {
                panic!("Hit a leaf node.");
            } else {
                let b = key.get_bit(level as usize);
                r = Key(sibling.0[b as usize * 4..(b as usize + 1) * 4]
                    .try_into()
                    .unwrap());
                level += 1;
            }
        }
        level -= 1;
        assert_eq!(
            r,
            Key([F::ZERO; 4]),
            "Tried to insert a hash node in a non-empty node."
        );

        if level >= 0 {
            let b = key.get_bit(level as usize) as usize * 4;
            siblings[level as usize].0[b..b + 4].copy_from_slice(&hash.elements);
        } else {
            new_root = hash;
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
                let b = key.get_bit(level as usize) as usize * 4;
                siblings[level as usize].0[b..b + 4].copy_from_slice(&new_root.elements);
            }
        }
        self.root = new_root;
    }

    /// Serialize and prune the SMT into a vector of U256.
    /// Starts with a [0, 0] for convenience, that way `ptr=0` is a canonical
    /// empty node. Therefore the root of the SMT is at `ptr=2`.
    /// `keys` is a list of keys whose prefixes will not be hashed-out in the
    /// serialization.
    /// Serialization rules:
    /// ```pseudocode
    /// serialize( HashNode { h } ) = [HASH_TYPE, h]
    /// serialize( InternalNode { left, right } ) = [INTERNAL_TYPE, serialize(left).ptr, serialize(right).ptr]
    /// serialize( LeafNode { rem_key, value } ) = [LEAF_TYPE, rem_key, value]
    /// ```
    pub fn serialize_and_prune<K: Borrow<Key>, I: IntoIterator<Item = K>>(
        &self,
        keys: I,
    ) -> Vec<U256> {
        let mut v = vec![U256::zero(); 2]; // For empty hash node.
        let key = Key(self.root.elements);

        let mut keys_to_include = HashSet::new();
        for key in keys.into_iter() {
            let mut bits = key.borrow().split();
            loop {
                keys_to_include.insert(bits);
                if bits.is_empty() {
                    break;
                }
                bits.pop_next_bit();
            }
        }

        serialize(self, key, &mut v, Bits::empty(), &keys_to_include);
        if v.len() == 2 {
            v.extend([U256::zero(); 2]);
        }
        v
    }

    pub fn serialize(&self) -> Vec<U256> {
        // Include all keys.
        self.serialize_and_prune(self.kv_store.keys())
    }
}

fn serialize<D: Db>(
    smt: &Smt<D>,
    key: Key,
    v: &mut Vec<U256>,
    cur_bits: Bits,
    keys_to_include: &HashSet<Bits>,
) -> usize {
    if key.0.iter().all(F::is_zero) {
        return 0; // `ptr=0` is an empty node.
    }

    if !keys_to_include.contains(&cur_bits) || smt.db.get_node(&key).is_none() {
        let index = v.len();
        v.push(HASH_TYPE.into());
        v.push(key2u(key));
        index
    } else if let Some(node) = smt.db.get_node(&key) {
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
            let i_left =
                serialize(smt, key_left, v, cur_bits.add_bit(false), keys_to_include).into();
            v[index + 1] = i_left;
            let i_right =
                serialize(smt, key_right, v, cur_bits.add_bit(true), keys_to_include).into();
            v[index + 2] = i_right;
            index
        }
    } else {
        unreachable!()
    }
}

/// Hash a serialized state SMT, i.e., one where leaves hold accounts.
pub fn hash_serialize(v: &[U256]) -> HashOut {
    _hash_serialize(v, 2)
}

pub fn hash_serialize_u256(v: &[U256]) -> U256 {
    hashout2u(hash_serialize(v))
}

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
