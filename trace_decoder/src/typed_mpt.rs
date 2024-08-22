//! Principled MPT types used in this library.

use core::fmt;
use std::{collections::HashMap, iter, marker::PhantomData};

use copyvec::CopyVec;
use ethereum_types::{Address, BigEndianHash as _, H256, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use itertools::Itertools;
use mpt_trie::{
    partial_trie::{HashedPartialTrie, Node, OnOrphanedHashNode, PartialTrie as _},
    trie_ops::TrieOpError,
};
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};
use u4::{u4, AsNibbles, U4x2, U4};

/// Map where keys are [up to 64 nibbles](TrieKey),
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
    const PANIC_MSG: &str = "T encoding/decoding should round-trip,\
    and only encoded `T`s are ever inserted";
    fn new() -> Self {
        Self {
            inner: HashedPartialTrie::new(Node::Empty),
            _ty: PhantomData,
        }
    }
    /// Insert a node which represents an out-of-band sub-trie.
    fn insert_hash(&mut self, key: TrieKey, hash: H256) -> Result<(), Error> {
        self.inner
            .insert(key.into_nibbles(), hash)
            .map_err(|source| Error { source })
    }
    /// Returns an [`Error`] if the `key` crosses into a part of the trie that
    /// isn't hydrated.
    fn insert(&mut self, key: TrieKey, value: T) -> Result<Option<T>, Error>
    where
        T: rlp::Encodable + rlp::Decodable,
    {
        let prev = self.get(key);
        self.inner
            .insert(key.into_nibbles(), rlp::encode(&value).to_vec())
            .map_err(|source| Error { source })
            .map(|_| prev)
    }
    /// Note that this returns [`None`] if `key` crosses into a part of the
    /// trie that isn't hydrated.
    ///
    /// # Panics
    /// - If [`rlp::decode`]-ing for `T` doesn't round-trip.
    fn get(&self, key: TrieKey) -> Option<T>
    where
        T: rlp::Decodable,
    {
        let bytes = self.inner.get(key.into_nibbles())?;
        Some(rlp::decode(bytes).expect(Self::PANIC_MSG))
    }
    fn remove(&mut self, key: TrieKey) -> Result<Option<T>, Error>
    where
        T: rlp::Decodable,
    {
        match self.inner.delete(key.into_nibbles()) {
            Ok(Some(it)) => Ok(Some(rlp::decode(&it).expect(Self::PANIC_MSG))),
            Ok(None) => Ok(None),
            Err(source) => Err(Error { source }),
        }
    }
    fn as_hashed_partial_trie(&self) -> &HashedPartialTrie {
        &self.inner
    }
    fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.inner
    }
    fn root(&self) -> H256 {
        self.inner.hash()
    }
    /// Note that this returns owned paths and items.
    fn iter(&self) -> impl Iterator<Item = (TrieKey, T)> + '_
    where
        T: rlp::Decodable,
    {
        self.inner.keys().filter_map(|nib| {
            let path = TrieKey::from_nibbles(nib);
            Some((path, self.get(path)?))
        })
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
    type Item = (TrieKey, T);
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
pub struct TrieKey(CopyVec<U4, 64>);

impl fmt::Display for TrieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for u in self.0 {
            f.write_fmt(format_args!("{:x}", u))?
        }
        Ok(())
    }
}

impl TrieKey {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        Ok(TrieKey(CopyVec::try_from_iter(components)?))
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

    pub fn from_txn_ix(txn_ix: usize) -> Self {
        TrieKey::new(AsNibbles(rlp::encode(&txn_ix))).expect(
            "\
            rlp of an usize goes through a u64, which is 8 bytes,
            which will be 9 bytes RLP'ed.
            9 < 32",
        )
    }
    pub fn into_nibbles(self) -> mpt_trie::nibbles::Nibbles {
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
            .get(TrieKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TrieKey::from_txn_ix(txn_ix).into_nibbles(), val)
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
            .get(TrieKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TrieKey::from_txn_ix(txn_ix).into_nibbles(), val)
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
    pub fn new(strategy: OnOrphanedHashNode) -> Self {
        Self {
            typed: TypedMpt {
                inner: HashedPartialTrie::new_with_strategy(Node::Empty, strategy),
                _ty: PhantomData,
            },
        }
    }
    pub fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> Result<Option<AccountRlp>, Error> {
        #[allow(deprecated)]
        self.insert_by_key(TrieKey::from_address(address), account)
    }
    #[deprecated = "prefer operations on `Address` where possible, as SMT support requires this"]
    pub fn insert_by_key(
        &mut self,
        key: TrieKey,
        account: AccountRlp,
    ) -> Result<Option<AccountRlp>, Error> {
        self.typed.insert(key, account)
    }
    pub fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) -> Result<(), Error> {
        self.typed.insert_hash(key, hash)
    }
    pub fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.typed
            .get(TrieKey::from_hash(keccak_hash::keccak(address)))
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
    pub fn iter(&self) -> impl Iterator<Item = (TrieKey, AccountRlp)> + '_ {
        self.typed.iter()
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        self.typed.as_mut_hashed_partial_trie_unchecked()
    }
    pub fn remove_address(&mut self, address: Address) -> Result<Option<AccountRlp>, Error> {
        self.typed.remove(TrieKey::from_address(address))
    }
    pub fn contains_address(&self, address: Address) -> bool {
        self.typed
            .as_hashed_partial_trie()
            .contains(TrieKey::from_address(address).into_nibbles())
    }
    /// This allows users to break the [`TypedMpt`] invariant.
    /// If data that isn't a [`rlp::encode`]-ed [`AccountRlp`] is inserted,
    /// subsequent API calls may panic.
    pub fn from_hashed_partial_trie_unchecked(
        src: mpt_trie::partial_trie::HashedPartialTrie,
    ) -> Self {
        Self {
            typed: TypedMpt {
                inner: src,
                _ty: PhantomData,
            },
        }
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
    pub fn new(strategy: OnOrphanedHashNode) -> Self {
        Self {
            untyped: HashedPartialTrie::new_with_strategy(Node::Empty, strategy),
        }
    }
    pub fn insert(&mut self, key: TrieKey, value: Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        let prev = self.untyped.get(key.into_nibbles()).map(Vec::from);
        self.untyped
            .insert(key.into_nibbles(), value)
            .map_err(|source| Error { source })?;
        Ok(prev)
    }
    pub fn insert_hash(&mut self, key: TrieKey, hash: H256) -> Result<(), Error> {
        self.untyped
            .insert(key.into_nibbles(), hash)
            .map_err(|source| Error { source })
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub fn as_hashed_partial_trie(&self) -> &HashedPartialTrie {
        &self.untyped
    }

    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.untyped
    }
}

pub struct StateSmt {
    address2state: HashMap<Address, AccountRlp>,
    deferred: HashMap<TrieKey, H256>,
}

impl StateSmt {
    pub fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> Result<Option<AccountRlp>, Error> {
        Ok(self.address2state.insert(address, account))
    }
    pub fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) -> Result<(), Error> {
        self.deferred.insert(key, hash);
        Ok(())
    }
    pub fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.address2state.get(&address).copied()
    }
    pub fn root(&self) -> H256 {
        let mut smt = smt_trie::smt::Smt::<smt_trie::db::MemoryDb>::default();

        for (key, hash) in &self.deferred {
            // "needs to be called before `set` to avoid any issues"
            smt.set_hash(key2key(*key).split(), hash2hash(*hash));
        }

        for (
            addr,
            AccountRlp {
                nonce,
                balance,
                storage_root,
                code_hash,
            },
        ) in &self.address2state
        {
            smt.set(smt_trie::keys::key_nonce(*addr), *nonce);
            smt.set(smt_trie::keys::key_balance(*addr), *balance);
            // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
            //                is this the correct storage slot?
            smt.set(
                smt_trie::keys::key_storage(*addr, U256::zero()),
                storage_root.into_uint(),
            );
            smt.set(smt_trie::keys::key_code(*addr), code_hash.into_uint())
        }

        let HashOut { elements } = smt.root;
        let mut bytes = [0; 32];
        for (dst, src) in bytes.iter_mut().zip_eq(
            elements
                .into_iter()
                .flat_map(|GoldilocksField(u)| u.to_ne_bytes()),
        ) {
            *dst = src
        }

        H256(bytes)
    }
}

fn hash2hash(H256(ours): H256) -> HashOut<GoldilocksField> {
    todo!()
}

fn key2key(TrieKey(ours): TrieKey) -> smt_trie::smt::Key {
    const FIELD_PER_KEY: usize = 4;
    const BYTE_PER_FIELD: usize = 8;

    let mut bytes = [0u8; BYTE_PER_FIELD * FIELD_PER_KEY];
    for (ix, U4x2 { packed }) in Pack::new(ours).enumerate() {
        bytes[ix] = packed
    }

    let mut chunks = bytes.chunks_exact(BYTE_PER_FIELD);

    // no unsafe, no unstable
    let theirs = smt_trie::smt::Key(core::array::from_fn(|_ix| {
        GoldilocksField(u64::from_ne_bytes(
            <[u8; BYTE_PER_FIELD]>::try_from(chunks.next().unwrap()).unwrap(),
        ))
    }));
    assert_eq!(chunks.len(), 0);
    theirs
}

/// [`Iterator`] which turns [`U4`]s into [`U4x2`]s, `0`-padding if required.
struct Pack<I> {
    inner: iter::Fuse<I>,
}

impl<I> Pack<I> {
    fn new<II: IntoIterator<IntoIter = I>>(inner: II) -> Self
    where
        I: Iterator,
    {
        Self {
            inner: inner.into_iter().fuse(),
        }
    }
}

impl<I> Iterator for Pack<I>
where
    I: Iterator<Item = U4>,
{
    type Item = U4x2;
    fn next(&mut self) -> Option<Self::Item> {
        match (self.inner.next(), self.inner.next()) {
            (None, None) => None,
            (Some(pad), None) => Some(U4x2::new(pad, u4!(0))),
            (None, Some(_)) => unreachable!("iterator is fused, so Some cannot follow None"),
            (Some(left), Some(right)) => Some(U4x2::new(left, right)),
        }
    }
}

#[test]
fn test_key2key() {
    let nibbles = &iter::successors(Some(u4!(0)), |it| it.checked_add(u4!(1))).cycle();
    for len in 0.. {
        match TrieKey::new(nibbles.clone().take(len)) {
            Ok(key) => {
                let _did_not_panic = key2key(key);
            }
            Err(_) => break, // too long
        }
    }
}
