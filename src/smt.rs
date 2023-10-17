use std::collections::BTreeMap;

use ethereum_types::{BigEndianHash, H256, U256};

use crate::{
    account::Account,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValOrHash {
    Val(Account),
    Hash(H256),
}
impl ValOrHash {
    pub fn is_val(&self) -> bool {
        matches!(self, ValOrHash::Val(_))
    }

    pub fn is_hash(&self) -> bool {
        matches!(self, ValOrHash::Hash(_))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValOrHashNode {
    Val { key: Bits, account: Account },
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
            ValOrHashNode::Val { key, account } => hash_leaf(*key, account.hash()),
            ValOrHashNode::Hash(h) => *h,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalNode([H256; RADIX]);

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
    pub fn new<I>(iter: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (Bits, ValOrHash)>,
    {
        let mut smt = Smt {
            leaves: BTreeMap::new(),
            internal_nodes: BTreeMap::new(),
            root: DEFAULT_HASH,
        };
        for (key, value) in iter {
            smt.insert(key, value)?;
        }
        Ok(smt)
    }
    pub fn is_empty(&self) -> bool {
        let empty = self.root == DEFAULT_HASH;
        if empty {
            assert!(self.leaves.is_empty());
            assert!(self.internal_nodes.is_empty());
        }
        empty
    }

    pub fn insert(&mut self, key: Bits, value: ValOrHash) -> Result<(), Error> {
        if value.is_val() && key.count != 256 {
            return Err("Key must be 256 bits".to_string());
        }

        let node = match value {
            ValOrHash::Val(account) => ValOrHashNode::Val { key, account },
            ValOrHash::Hash(h) => ValOrHashNode::Hash(h),
        };
        let hash = node.hash();
        if self.is_empty() {
            self.root = hash;
            self.leaves.insert(Bits::empty(), node);
            return Ok(());
        }
        let mut partial_key = key;
        let mut last_bit = None;
        loop {
            // Check if leaves[key] exists, and if so if it's consistent with the new value.
            if let Some(existing) = self.leaves.get(&partial_key).cloned() {
                if existing.hash() == hash {
                    return Ok(());
                }
                if let ValOrHashNode::Val { key: k, .. } = existing {
                    if k == key {
                        return Err("Key already exists. Use update instead.".to_string());
                    }
                    // We need to create a new internal node.
                    let (common_prefix, bits) = key.common_prefix(&k);
                    let (n_bit, o_bit) = bits.ok_or_else(|| "Error".to_string())?;
                    let new_node = InternalNode(if n_bit {
                        [existing.hash(), hash]
                    } else {
                        [hash, existing.hash()]
                    });
                    self.leaves.remove(&partial_key);
                    self.leaves.insert(common_prefix.add_bit(n_bit), node);
                    self.leaves.insert(common_prefix.add_bit(o_bit), existing);
                    let mut internal_hash = new_node.hash();
                    self.internal_nodes.insert(common_prefix, new_node);
                    let mut internal_key = common_prefix;
                    while internal_key.count > 0 {
                        let bit = internal_key.pop_next_bit();
                        if self.leaves.contains_key(&internal_key) {
                            return Err("There is a hash node above this key1.".to_string());
                        }
                        let node = self
                            .internal_nodes
                            .entry(internal_key)
                            .or_insert_with(|| InternalNode([DEFAULT_HASH; RADIX]));
                        node.0[bit as usize] = internal_hash;
                        internal_hash = node.hash();
                    }
                    self.root = internal_hash;
                    return Ok(());
                } else {
                    return Err("There is a hash node above this key2.".to_string());
                }
            } else if let Some(existing) = self.internal_nodes.get(&partial_key).cloned() {
                let last_bit = last_bit.ok_or_else(|| "Error".to_string())?;
                assert_eq!(existing.0[last_bit as usize], DEFAULT_HASH);
                self.internal_nodes.get_mut(&partial_key).unwrap().0[last_bit as usize] = hash;
                self.leaves.insert(partial_key.add_bit(last_bit), node);
                let mut internal_key = partial_key;
                let mut internal_hash = self.internal_nodes.get(&partial_key).unwrap().hash();
                while internal_key.count > 0 {
                    let bit = internal_key.pop_next_bit();
                    if self.leaves.contains_key(&internal_key) {
                        return Err("There is a hash node above this key3.".to_string());
                    }
                    let node = self
                        .internal_nodes
                        .entry(internal_key)
                        .or_insert_with(|| InternalNode([DEFAULT_HASH; RADIX]));
                    node.0[bit as usize] = internal_hash;
                    internal_hash = node.hash();
                }
                self.root = internal_hash;
                return Ok(());
            }
            last_bit = Some(partial_key.pop_next_bit());
        }
    }

    pub fn serialize(&self) -> Vec<U256> {
        let mut v = vec![];
        let key = Bits::empty();
        serialize(self, key, &mut v);
        v
    }
}

fn serialize(smt: &Smt, key: Bits, v: &mut Vec<U256>) -> usize {
    if let Some(node) = smt.leaves.get(&key) {
        match node {
            ValOrHashNode::Val { key, account } => {
                let index = v.len();
                v.push(LEAF_TYPE.into());
                assert_eq!(key.count, 256);
                v.push(key.packed);
                v.extend(account.pack_u256());
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

pub fn hash_serialize(v: &[U256]) -> H256 {
    _hash_serialize(v, 0)
}

fn _hash_serialize(v: &[U256], ptr: usize) -> H256 {
    assert!(v[ptr] <= u8::MAX.into());
    match v[ptr].as_u64() as u8 {
        HASH_TYPE => H256(v[ptr + 1].into()),

        INTERNAL_TYPE => {
            let mut node = InternalNode([DEFAULT_HASH; RADIX]);
            for b in 0..RADIX {
                let child_index = v[ptr + 1 + b];
                let child_hash = _hash_serialize(v, child_index.as_usize());
                node.0[b] = child_hash;
            }
            node.hash()
        }
        LEAF_TYPE => {
            let key = Bits::from(v[ptr + 1]);
            let nonce = v[ptr + 2].as_u64();
            let balance = v[ptr + 3];
            let storage_root = u2h(v[ptr + 4]);
            let code_hash = u2h(v[ptr + 5]);
            let account = Account {
                nonce,
                balance,
                storage_root,
                code_hash,
            };
            hash_leaf(key, account.hash())
        }
        _ => panic!("Should not happen"),
    }
}

#[cfg(test)]
mod tests {
    use ethereum_types::U256;
    use rand::{seq::SliceRandom, thread_rng, Rng};

    use crate::smt::hash_serialize;

    use super::{Smt, ValOrHash};

    #[test]
    fn test_small_smt() -> Result<(), String> {
        let mut rng = thread_rng();
        let account0 = rng.gen();
        let account1 = rng.gen();

        let nodes = [
            (U256::from(3).into(), ValOrHash::Val(account0)),
            (U256::one().into(), ValOrHash::Val(account1)),
        ];
        let smt0 = Smt::new(nodes)?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize(&v), smt0.root);

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
        let account0 = rng.gen();
        let account1 = rng.gen();

        let nodes = [
            (
                U256::from_dec_str(
                    "57896044618658097711785492504343953926634992332820282019728792003956564819968",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account0),
            ),
            (
                U256::from_dec_str(
                    "86844066927987146567678238756515930889952488499230423029593188005934847229952",
                )
                .unwrap()
                .into(),
                ValOrHash::Val(account1),
            ),
        ];
        let smt0 = Smt::new(nodes)?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize(&v), smt0.root);

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
        let n = 10000;
        let mut rng = thread_rng();
        let rand_node = |_| (U256(rng.gen()).into(), ValOrHash::Val(rng.gen()));
        let mut rand_nodes = (0..n).map(rand_node).collect::<Vec<_>>();
        let smt0 = Smt::new(rand_nodes.iter().cloned())?;
        let v = smt0.serialize();
        assert_eq!(hash_serialize(&v), smt0.root);

        rand_nodes.shuffle(&mut rng);
        let smt1 = Smt::new(rand_nodes)?;

        assert_eq!(smt0, smt1);

        Ok(())
    }
}
