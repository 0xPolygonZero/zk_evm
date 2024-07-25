//! Principled MPT types used in this library.

use std::marker::PhantomData;

use copyvec::CopyVec;
use ethereum_types::{Address, H256};
use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::{
    partial_trie::{HashedPartialTrie, Node, PartialTrie as _},
    trie_ops::TrieOpError,
};
use u4::{AsNibbles, U4};

/// Map where keys are [up to 64 nibbles](TriePath),
/// and values are [`rlp::Encodable`]/[`rlp::Decodable`].
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie>.
///
/// Portions of the trie may be deferred: see [`Self::insert_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct TypedMpt<T> {
    inner: HashedPartialTrie,
    _ty: PhantomData<fn() -> T>,
}

impl<T> TypedMpt<T> {
    fn new() -> Self {
        Self {
            inner: HashedPartialTrie::new(Node::Empty),
            _ty: PhantomData,
        }
    }
    /// Insert a node which represents an out-of-band sub-trie.
    fn insert_hash(&mut self, path: TriePath, hash: H256) -> Result<(), Error> {
        self.inner
            .insert(path.into_nibbles(), hash)
            .map_err(|source| Error { source })
    }
    /// Returns an [`Error`] if the `path` crosses into a part of the trie that
    /// isn't hydrated.
    fn insert(&mut self, path: TriePath, value: T) -> Result<Option<T>, Error>
    where
        T: rlp::Encodable + rlp::Decodable,
    {
        let prev = self.get(path);
        self.inner
            .insert(path.into_nibbles(), rlp::encode(&value).to_vec())
            .map_err(|source| Error { source })
            .map(|_| prev)
    }
    /// Note that this returns [`None`] if `path` crosses into a part of the
    /// trie that isn't hydrated.
    ///
    /// # Panics
    /// - If [`rlp::decode`]-ing for `T` doesn't round-trip.
    fn get(&self, path: TriePath) -> Option<T>
    where
        T: rlp::Decodable,
    {
        let bytes = self.inner.get(path.into_nibbles())?;
        Some(rlp::decode(bytes).expect(
            "T encoding/decoding should round-trip,\
            and only encoded `T`s are ever inserted",
        ))
    }
    /// # Panics
    /// - If [`rlp::decode`]-ing for `T` doesn't round-trip.
    fn remove(&mut self, path: TriePath) -> Result<Option<T>, Error>
    where
        T: rlp::Decodable,
    {
        match self.inner.delete(path.into_nibbles()) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => Ok(Some(rlp::decode(&bytes).expect(
                "T encoding/decoding should round-trip,\
                    and only encoded `T`s are ever inserted",
            ))),
            // TODO(0xaatif): why is this fallible if `get` isn't?
            Err(source) => Err(Error { source }),
        }
    }
    fn as_hashed_partial_trie(&self) -> &HashedPartialTrie {
        &self.inner
    }
    fn root(&self) -> H256 {
        self.inner.hash()
    }
    /// Note that this returns owned paths and items.
    fn iter(&self) -> impl Iterator<Item = (TriePath, T)> + '_
    where
        T: rlp::Decodable,
    {
        self.inner.keys().filter_map(|nib| {
            let path = TriePath::from_nibbles(nib);
            Some((path, self.get(path)?))
        })
    }
    /// This allows users to break the [`TypedMpt`] invariant.
    /// If data that isn't an [`rlp::encode`]-ed `T` is inserted,
    /// subsequent API calls may panic.
    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.inner
    }
}

impl<T> Default for TypedMpt<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, T> IntoIterator for &'a TypedMpt<T>
where
    T: rlp::Decodable,
{
    type Item = (TriePath, T);
    type IntoIter = Box<dyn Iterator<Item = Self::Item> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error {
    source: TrieOpError,
}

/// Bounded sequence of [`U4`],
/// used as a key for [`TypedMpt`].
///
/// Semantically equivalent to [`mpt_trie::nibbles::Nibbles`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
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
    pub fn from_hash(H256(bytes): H256) -> Self {
        Self::new(AsNibbles(bytes)).expect("32 bytes is 64 nibbles, which fits")
    }
    fn from_txn_ix(txn_ix: usize) -> Self {
        TriePath::new(AsNibbles(rlp::encode(&txn_ix))).expect(
            "\
            rlp of an usize goes through a u64, which is 8 bytes,
            which will be 9 bytes RLP'ed.
            9 < 32",
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

/// Per-block, `txn_ix -> [u8]`.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#receipts-trie>
#[derive(Debug, Clone, Default)]
pub struct TransactionTrie {
    untyped: HashedPartialTrie,
}

impl TransactionTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        let prev = self
            .untyped
            .get(TriePath::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TriePath::from_txn_ix(txn_ix).into_nibbles(), val)
            .map_err(|source| Error { source })?;
        Ok(prev)
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        &self.untyped
    }
}

/// Per-block, `txn_ix -> [u8]`.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#transaction-trie>
#[derive(Debug, Clone, Default)]
pub struct ReceiptTrie {
    untyped: HashedPartialTrie,
}

impl ReceiptTrie {
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        let prev = self
            .untyped
            .get(TriePath::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TriePath::from_txn_ix(txn_ix).into_nibbles(), val)
            .map_err(|source| Error { source })?;
        Ok(prev)
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        &self.untyped
    }
}

/// Global, [`Address`] `->` [`AccountRlp`].
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
    ) -> Result<Option<AccountRlp>, Error> {
        self.insert_by_path(TriePath::from_address(address), account)
    }
    pub fn insert_by_path(
        &mut self,
        path: TriePath,
        account: AccountRlp,
    ) -> Result<Option<AccountRlp>, Error> {
        self.typed.insert(path, account)
    }
    pub fn insert_hash_by_path(&mut self, path: TriePath, hash: H256) -> Result<(), Error> {
        self.typed.insert_hash(path, hash)
    }
    pub fn get_by_path(&self, path: TriePath) -> Option<AccountRlp> {
        self.typed.get(path)
    }
    pub fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.get_by_path(TriePath::from_hash(keccak_hash::keccak(address)))
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn iter(&self) -> impl Iterator<Item = (TriePath, AccountRlp)> + '_ {
        self.typed.iter()
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }

    /// This allows users to break the [`TypedMpt`] invariant.
    /// If data that isn't an [`rlp::encode`]-ed `T` is inserted,
    /// subsequent API calls may panic.
    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        self.typed.as_mut_hashed_partial_trie_unchecked()
    }
}

impl<'a> IntoIterator for &'a StateTrie {
    type Item = (TriePath, AccountRlp);

    type IntoIter = Box<dyn Iterator<Item = Self::Item> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.typed.into_iter()
    }
}

/// Global, per-account.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie>
#[derive(Debug, Clone, Default)]
pub struct StorageTrie {
    untyped: HashedPartialTrie,
}
impl StorageTrie {
    pub fn insert(&mut self, path: TriePath, value: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        let prev = self.untyped.get(path.into_nibbles()).map(Vec::from);
        self.untyped
            .insert(path.into_nibbles(), value)
            .map_err(|source| Error { source })?;
        Ok(prev)
    }
    pub fn insert_hash(&mut self, path: TriePath, hash: H256) -> Result<(), Error> {
        self.untyped
            .insert(path.into_nibbles(), hash)
            .map_err(|source| Error { source })
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub fn remove(&mut self, path: TriePath) -> Result<Option<Vec<u8>>, Error> {
        self.untyped
            .delete(path.into_nibbles())
            .map_err(|source| Error { source })
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        &self.untyped
    }

    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.untyped
    }
}

#[test]
fn test() {
    let hash = H256(std::array::from_fn(|ix| ix as _));
    let mut ours = StorageTrie::default();
    ours.insert_hash(TriePath::default(), hash).unwrap();
    assert_eq!(
        ours.as_hashed_partial_trie(),
        &HashedPartialTrie::new(Node::Hash(hash))
    );
}
