use std::collections::BTreeMap;

use ethereum_types::{BigEndianHash, H256, U256};

use crate::{
    account::{Account, AccountWithStorageRoot},
    bits::Bits,
    hash::{hash_internal, hash_leaf},
    utils::u2h,
};

pub const RADIX: usize = 2;
pub const DEFAULT_HASH: H256 = H256([0; 32]);

const HASH_TYPE: u8 = 0;
const INTERNAL_TYPE: u8 = 1;
const LEAF_TYPE: u8 = 2;

pub type Error = String;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AccountOrValue {
    Account(Account),
    Value(U256),
}

impl AccountOrValue {
    pub fn hash(&self) -> H256 {
        match self {
            AccountOrValue::Account(a) => a.hash(),
            AccountOrValue::Value(v) => u2h(*v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValOrHash {
    Val(AccountOrValue),
    Hash(H256),
}

impl ValOrHash {
    pub fn is_val(&self) -> bool {
        matches!(self, ValOrHash::Val(_))
    }

    pub fn is_hash(&self) -> bool {
        matches!(self, ValOrHash::Hash(_))
    }

    pub fn to_node(&self, rem_key: Bits) -> ValOrHashNode {
        match self {
            ValOrHash::Val(account) => ValOrHashNode::Val {
                rem_key,
                leaf: account.clone(),
            },
            ValOrHash::Hash(h) => ValOrHashNode::Hash(*h),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValOrHashNode {
    Val { rem_key: Bits, leaf: AccountOrValue },
    Hash(H256),
}

impl ValOrHashNode {
    pub fn is_val(&self) -> bool {
        matches!(self, ValOrHashNode::Val { .. })
    }

    pub fn is_hash(&self) -> bool {
        matches!(self, ValOrHashNode::Hash(_))
    }

    pub fn hash(&self) -> H256 {
        match self {
            ValOrHashNode::Val { rem_key, leaf } => hash_leaf(*rem_key, leaf.hash()),
            ValOrHashNode::Hash(h) => *h,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalNode([H256; RADIX]);

impl Default for InternalNode {
    fn default() -> Self {
        Self([DEFAULT_HASH; RADIX])
    }
}

impl InternalNode {
    pub fn hash(&self) -> H256 {
        hash_internal(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smt {
    pub leaves: BTreeMap<Bits, ValOrHashNode>,
    pub internal_nodes: BTreeMap<Bits, InternalNode>,
    pub root: H256,
}

impl Smt {
    pub fn empty() -> Self {
        Self {
            leaves: BTreeMap::from_iter([(Bits::empty(), ValOrHashNode::Hash(DEFAULT_HASH))]),
            internal_nodes: BTreeMap::new(),
            root: DEFAULT_HASH,
        }
    }

    pub fn new<I>(iter: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (Bits, ValOrHash)>,
    {
        let mut smt = Self::empty();
        for (key, value) in iter {
            smt.insert(key, value)?;
        }
        Ok(smt)
    }

    pub fn is_empty(&self) -> bool {
        let empty = self.root == DEFAULT_HASH;
        if empty {
            assert!(self.internal_nodes.is_empty());
            assert_eq!(
                self.leaves,
                BTreeMap::from_iter([(Bits::empty(), ValOrHashNode::Hash(DEFAULT_HASH))])
            );
        }
        empty
    }

    pub fn leaves<I>(self) -> Vec<(Bits, ValOrHash)> {
        self.leaves
            .into_iter()
            .map(|(k, v)| match v {
                ValOrHashNode::Val { rem_key, leaf } => (k + rem_key, ValOrHash::Val(leaf)),
                ValOrHashNode::Hash(h) => (k, ValOrHash::Hash(h)),
            })
            .collect()
    }

    fn insert_helper(
        &mut self,
        current_key: Bits,
        rem_key: Bits,
        value: &ValOrHash,
    ) -> Result<(), Error> {
        if self.internal_nodes.contains_key(&current_key) {
            let mut rem = rem_key;
            let new_key = current_key.add_bit(rem.pop_next_bit());
            return self.insert_helper(new_key, rem, value);
        }
        match self.leaves.get(&current_key) {
            Some(ValOrHashNode::Hash(h)) if h.is_zero() => {
                self.leaves.insert(current_key, value.to_node(rem_key));
                self.update_hashes(current_key);
            }
            Some(ValOrHashNode::Val { rem_key: k, leaf }) => {
                let k = *k;
                let leaf = leaf.clone();
                if k == rem_key {
                    return Err("Key already exists. Use update instead.".to_string());
                }
                self.internal_nodes
                    .insert(current_key, InternalNode::default());
                self.leaves.remove(&current_key);
                self.insert_helper(current_key, k, &ValOrHash::Val(leaf))?;
                self.insert_helper(current_key, rem_key, value)?;
            }
            None => {
                self.leaves.insert(current_key, value.to_node(rem_key));
                self.update_hashes(current_key);
            }
            _ => panic!("Should not happen"),
        }
        Ok(())
    }

    pub fn insert(&mut self, key: Bits, value: ValOrHash) -> Result<(), Error> {
        if value.is_val() && key.count != 256 {
            return Err("Key must be 256 bits".to_string());
        }
        self.insert_helper(Bits::empty(), key, &value)
    }

    pub fn serialize(&self) -> Vec<U256> {
        let mut v = vec![];
        let key = Bits::empty();
        serialize(self, key, &mut v);
        v
    }

    fn update_hashes(&mut self, current_key: Bits) {
        let leaf = self.leaves.get(&current_key).expect("Should exist");
        let mut hash = leaf.hash();
        let mut key = current_key;
        loop {
            if key.is_empty() {
                self.root = hash;
                return;
            }
            let bit = key.pop_next_bit();
            let internal = self.internal_nodes.get_mut(&key).expect("Should exist");
            internal.0[bit as usize] = hash;
            hash = internal.hash();
        }
    }
}

fn serialize(smt: &Smt, key: Bits, v: &mut Vec<U256>) -> usize {
    if let Some(node) = smt.leaves.get(&key) {
        match node {
            ValOrHashNode::Val { rem_key, leaf } => {
                let index = v.len();
                v.push(LEAF_TYPE.into());
                v.push((index + 2).into());
                v.push(rem_key.packed);
                match leaf {
                    AccountOrValue::Account(account) => {
                        v.extend(account.pack_u256());
                        let storage_smt_index = v.len();
                        v[storage_smt_index - 2] = storage_smt_index.into();
                        serialize(&account.storage_smt, Bits::empty(), v);
                    }
                    AccountOrValue::Value(val) => {
                        v.push(*val);
                    }
                }
                index
            }
            ValOrHashNode::Hash(h) => {
                let index = v.len();
                v.push(HASH_TYPE.into());
                v.push(h.0.into());
                index
            }
        }
    } else if smt.internal_nodes.contains_key(&key) {
        let index = v.len();
        v.push(INTERNAL_TYPE.into());
        for _ in 0..RADIX {
            v.push(U256::zero());
        }
        for b in 0..RADIX {
            let child_index = serialize(smt, key.add_bit(b == 1), v);
            v[1 + index + b] = child_index.into();
        }
        index
    } else {
        // Empty node
        let index = v.len();
        v.push(HASH_TYPE.into());
        v.push(DEFAULT_HASH.into_uint());
        index
    }
}

pub fn hash_serialize_state(v: &[U256]) -> H256 {
    _hash_serialize(v, 0, false)
}

pub fn hash_serialize_storage(v: &[U256]) -> H256 {
    _hash_serialize(v, 0, true)
}

fn _hash_serialize(v: &[U256], ptr: usize, storage: bool) -> H256 {
    assert!(v[ptr] <= u8::MAX.into());
    match v[ptr].as_u64() as u8 {
        HASH_TYPE => H256(v[ptr + 1].into()),

        INTERNAL_TYPE => {
            let mut node = InternalNode([DEFAULT_HASH; RADIX]);
            for b in 0..RADIX {
                let child_index = v[ptr + 1 + b];
                let child_hash = _hash_serialize(v, child_index.as_usize(), storage);
                node.0[b] = child_hash;
            }
            node.hash()
        }
        LEAF_TYPE => {
            let ptr = v[ptr + 1].as_usize();
            let key = Bits::from(v[ptr]);
            if storage {
                let val = v[ptr + 1];
                hash_leaf(key, AccountOrValue::Value(val).hash())
            } else {
                let nonce = v[ptr + 1].as_u64();
                let balance = v[ptr + 2];
                let storage_smt_root_index = v[ptr + 3].as_usize();
                let storage_smt_root = _hash_serialize(v, storage_smt_root_index, true);
                let code_hash = u2h(v[ptr + 4]);
                let account = AccountWithStorageRoot {
                    nonce,
                    balance,
                    storage_smt_root,
                    code_hash,
                };
                hash_leaf(key, account.hash())
            }
        }
        _ => panic!("Should not happen"),
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::U256;
    use rand::{seq::SliceRandom, thread_rng, Rng};

    use crate::smt::{hash_serialize_state, AccountOrValue};

    use super::{Smt, ValOrHash};

    #[test]
    fn test_small_smt() -> Result<(), String> {
        let mut rng = thread_rng();
        let account0 = AccountOrValue::Account(rng.gen());
        let account1 = AccountOrValue::Account(rng.gen());

        let nodes = [
            (U256::from(3).into(), ValOrHash::Val(account0.clone())),
            (U256::one().into(), ValOrHash::Val(account1.clone())),
        ];
        let smt0 = Smt::new(nodes)?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize_state(&v), smt0.root);

        let nodes = [
            (U256::one().into(), ValOrHash::Val(account1)),
            (U256::from(3).into(), ValOrHash::Val(account0)),
        ];
        let smt1 = Smt::new(nodes)?;

        assert_eq!(smt0, smt1);

        Ok(())
    }

    #[test]
    fn test_small_smt_bis() -> Result<(), String> {
        let mut rng = thread_rng();
        let account0 = AccountOrValue::Account(rng.gen());
        let account1 = AccountOrValue::Account(rng.gen());

        let nodes = [
            (
                U256::from_dec_str(
                    "57896044618658097711785492504343953926634992332820282019728792003956564819968",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account0.clone()),
            ),
            (
                U256::from_dec_str(
                    "86844066927987146567678238756515930889952488499230423029593188005934847229952",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account1.clone()),
            ),
        ];
        let smt0 = Smt::new(nodes)?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize_state(&v), smt0.root);

        let nodes = [
            (
                U256::from_dec_str(
                    "86844066927987146567678238756515930889952488499230423029593188005934847229952",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account1),
            ),
            (
                U256::from_dec_str(
                    "57896044618658097711785492504343953926634992332820282019728792003956564819968",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account0),
            ),
        ];
        let smt1 = Smt::new(nodes)?;

        assert_eq!(smt0, smt1);

        Ok(())
    }

    #[test]
    fn test_random_smt() -> Result<(), String> {
        let n = 1000;
        let mut rng = thread_rng();
        let rand_node = |_| {
            (
                U256(rng.gen()).into(),
                ValOrHash::Val(AccountOrValue::Account(rng.gen())),
            )
        };
        let mut rand_nodes = (0..n).map(rand_node).collect::<Vec<_>>();
        let smt0 = Smt::new(rand_nodes.iter().cloned())?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize_state(&v), smt0.root);

        rand_nodes.shuffle(&mut rng);
        let smt1 = Smt::new(rand_nodes)?;

        assert_eq!(smt0, smt1);

        Ok(())
    }
}
