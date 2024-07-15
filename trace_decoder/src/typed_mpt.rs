//! Principled MPT types used in this library.

use std::collections::BTreeMap;

use copyvec::CopyVec;
use either::Either;
use ethereum_types::{Address, H256};
use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::partial_trie::PartialTrie as _;
use u4::{AsNibbles, U4};

/// Bounded sequence of [`U4`],
/// used as a key for [`TypedMpt`].
///
/// Semantically equivalent to [`mpt_trie::nibbles::Nibbles`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TriePath(CopyVec<U4, 64>);

impl TriePath {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        Ok(TriePath(CopyVec::try_from_iter(components)?))
    }
    pub fn into_hash_left_padded(mut self) -> H256 {
        for _ in 0..self.0.spare_capacity_mut().len() {
            self.0.insert(0, U4::Dec00)
        }
        let mut packed = [0u8; 32];
        AsNibbles(&mut packed).pack_from_slice(&self.0);
        H256::from_slice(&packed)
    }
    fn from_address(address: Address) -> Self {
        Self::from_hash(keccak_hash::keccak(address))
    }
    fn from_hash(H256(bytes): H256) -> Self {
        Self::new(AsNibbles(bytes)).expect("32 bytes is 64 nibbles, which fits")
    }
    fn from_txn_ix(txn_ix: usize) -> Self {
        TriePath::new(AsNibbles(rlp::encode(&txn_ix))).expect(
            "\
            rlp of an usize goes through a u64, which is 8 bytes,
            which will be 9 bytes RLP'ed.
            9 < 32
        ",
        )
    }
    fn into_nibbles(self) -> mpt_trie::nibbles::Nibbles {
        let mut theirs = mpt_trie::nibbles::Nibbles::default();
        for component in self.0 {
            theirs.push_nibble_back(component as u8)
        }
        theirs
    }
    pub fn from_nibbles(mut theirs: mpt_trie::nibbles::Nibbles) -> Self {
        let mut ours = CopyVec::new();
        while !theirs.is_empty() {
            ours.try_push(
                U4::new(theirs.pop_next_nibble_front())
                    .expect("mpt_trie returned an invalid nibble"),
            )
            .expect("mpt_trie should not have more than 64 nibbles")
        }
        Self(ours)
    }
}

/// Map where keys are [up to 64 nibbles](TriePath), and values are either an
/// out-of-band [hash](H256) or an inline [`rlp::Encodable`]/[`rlp::Decodable`]
/// value.
///
/// [Merkle Patricia Trees](https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie)
/// are _maps_, where keys are typically _sequences_ of an _alphabet_.
///
/// Map values are typically indirect (i.e a _hash_),
/// but in this structure may be stored _inline_.
///
/// Semantically equivalent to a [`mpt_trie::partial_trie::HashedPartialTrie`].
#[derive(Debug, Clone)]
struct TypedMpt<T> {
    map: BTreeMap<TriePath, Either<H256, T>>,
}

impl<T> Default for TypedMpt<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> TypedMpt<T> {
    pub const fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
    // pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, T>> {
    //     self.map.remove(&path)
    // }
    pub fn insert(&mut self, path: TriePath, value: T) -> Option<Either<H256, T>> {
        self.map.insert(path, Either::Right(value))
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, T>> {
        self.map.insert(path, Either::Left(hash))
    }
    // pub fn get(&self, path: TriePath) -> Option<Either<H256, &T>> {
    //     self.map.get(&path).map(|it| it.as_ref().map_left(|it| *it))
    // }
    pub fn root(&self) -> H256
    where
        T: rlp::Encodable,
    {
        self.as_hashed_partial_trie().hash()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&TriePath, &Either<H256, T>)> {
        self.map.iter()
    }
    pub fn as_hashed_partial_trie(&self) -> mpt_trie::partial_trie::HashedPartialTrie
    where
        T: rlp::Encodable,
    {
        let mut theirs = mpt_trie::partial_trie::HashedPartialTrie::default();
        for (path, v) in &self.map {
            let nibbles = path.into_nibbles();
            match v {
                Either::Left(h) => theirs.insert(nibbles, *h),
                Either::Right(v) => theirs.insert(nibbles, &*rlp::encode(v)),
            }
            .expect("internal error in legacy MPT library")
        }
        theirs
    }
}

impl<'a, T> IntoIterator for &'a TypedMpt<T> {
    type Item = (&'a TriePath, &'a Either<H256, T>);

    type IntoIter = Box<dyn Iterator<Item = (&'a TriePath, &'a Either<H256, T>)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

impl<T> IntoIterator for TypedMpt<T>
where
    T: 'static,
{
    type Item = (TriePath, Either<H256, T>);

    type IntoIter = Box<dyn Iterator<Item = (TriePath, Either<H256, T>)>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.map.into_iter())
    }
}

/// Per-block, keyed by transaction index.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#receipts-trie>
#[derive(Debug, Clone, Default)]
pub struct TransactionTrie {
    typed: TypedMpt<Vec<u8>>,
}

impl TransactionTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.typed.insert(TriePath::from_txn_ix(txn_ix), val)
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn as_hashed_partial_trie(&self) -> mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
}

/// Per-block, keyed by transaction index.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#transaction-trie>
#[derive(Debug, Clone, Default)]
pub struct ReceiptTrie {
    typed: TypedMpt<Vec<u8>>,
}

impl ReceiptTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) {
        self.typed.insert(TriePath::from_txn_ix(txn_ix), val);
    }
    pub fn as_hashed_partial_trie(&self) -> mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
}

/// Global, keyed by address
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie>
#[derive(Debug, Clone, Default)]
pub struct StateTrie {
    typed: TypedMpt<AccountRlp>,
}

impl StateTrie {
    pub fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> Option<Either<H256, AccountRlp>> {
        self.insert_by_path(TriePath::from_address(address), account)
    }
    pub fn insert_by_path(
        &mut self,
        path: TriePath,
        account: AccountRlp,
    ) -> Option<Either<H256, AccountRlp>> {
        self.typed.insert(path, account)
    }
    pub fn insert_branch_by_path(
        &mut self,
        path: TriePath,
        hash: H256,
    ) -> Option<Either<H256, AccountRlp>> {
        self.typed.insert_branch(path, hash)
    }
    pub fn get_by_path(&self, path: TriePath) -> Option<Either<H256, AccountRlp>> {
        self.typed.map.get(&path).copied()
    }
    pub fn get_by_address(&self, address: Address) -> Option<Either<H256, AccountRlp>> {
        self.get_by_path(TriePath::from_hash(keccak_hash::keccak(address)))
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&TriePath, &Either<H256, AccountRlp>)> {
        self.typed.iter()
    }
    pub fn as_hashed_partial_trie(&self) -> mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
}

impl IntoIterator for StateTrie {
    type Item = (TriePath, Either<H256, AccountRlp>);

    type IntoIter = Box<dyn Iterator<Item = (TriePath, Either<H256, AccountRlp>)>>;

    fn into_iter(self) -> Self::IntoIter {
        self.typed.into_iter()
    }
}

/// Global, per-account.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie>
#[derive(Debug, Clone, Default)]
pub struct StorageTrie {
    /// This does NOT use [`TypedMpt`] - T could be anything!
    map: BTreeMap<TriePath, Either<H256, Vec<u8>>>,
}
impl StorageTrie {
    pub fn insert(&mut self, path: TriePath, value: Vec<u8>) -> Option<Either<H256, Vec<u8>>> {
        self.map.insert(path, Either::Right(value))
    }
    pub fn insert_branch(&mut self, path: TriePath, hash: H256) -> Option<Either<H256, Vec<u8>>> {
        self.map.insert(path, Either::Left(hash))
    }
    pub fn root(&self) -> H256 {
        self.as_hashed_partial_trie().hash()
    }
    pub fn remove(&mut self, path: TriePath) -> Option<Either<H256, Vec<u8>>> {
        self.map.remove(&path)
    }
    pub fn as_hashed_partial_trie(&self) -> mpt_trie::partial_trie::HashedPartialTrie {
        let mut theirs = mpt_trie::partial_trie::HashedPartialTrie::default();
        for (k, v) in &self.map {
            let nibbles = k.into_nibbles();
            match v {
                Either::Left(h) => theirs.insert(nibbles, *h),
                // TODO(0xaatif): why is RLP-encoding here the right thing to do?
                //                (Our tests fail without it).
                Either::Right(v) => theirs.insert(nibbles, &*rlp::encode(v)),
            }
            .expect("error in mpt_trie")
        }
        theirs
    }
}
