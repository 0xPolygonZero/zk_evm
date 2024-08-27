//! Principled MPT types used in this library.

use core::fmt;
use std::{collections::BTreeMap, marker::PhantomData};

use copyvec::CopyVec;
use ethereum_types::{Address, H256};
use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::partial_trie::{HashedPartialTrie, Node, OnOrphanedHashNode, PartialTrie as _};
use u4::{AsNibbles, U4};

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
    fn insert_hash(&mut self, key: TrieKey, hash: H256) -> anyhow::Result<()> {
        self.inner.insert(key.into_nibbles(), hash)?;
        Ok(())
    }
    /// Returns an [`Error`] if the `key` crosses into a part of the trie that
    /// isn't hydrated.
    fn insert(&mut self, key: TrieKey, value: T) -> anyhow::Result<Option<T>>
    where
        T: rlp::Encodable + rlp::Decodable,
    {
        let prev = self.get(key);
        self.inner
            .insert(key.into_nibbles(), rlp::encode(&value).to_vec())?;
        Ok(prev)
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
    pub fn from_address(address: Address) -> Self {
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

    pub fn into_hash(self) -> Option<H256> {
        let Self(nibbles) = self;
        let mut bytes = [0; 32];
        AsNibbles(&mut bytes).pack_from_slice(&nibbles.into_array()?);
        Some(H256(bytes))
    }
}

#[test]
fn key_into_hash() {
    assert_eq!(TrieKey::new([]).unwrap().into_hash(), None);
    assert_eq!(
        TrieKey::new(itertools::repeat_n(u4::u4!(0), 64))
            .unwrap()
            .into_hash(),
        Some(H256::zero())
    )
}

/// Per-block, `txn_ix -> [u8]`.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#receipts-trie>
#[derive(Debug, Clone, Default)]
pub struct TransactionTrie {
    untyped: HashedPartialTrie,
}

impl TransactionTrie {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let prev = self
            .untyped
            .get(TrieKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TrieKey::from_txn_ix(txn_ix).into_nibbles(), val)?;
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
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let prev = self
            .untyped
            .get(TrieKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(TrieKey::from_txn_ix(txn_ix).into_nibbles(), val)?;
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
pub struct StateMpt {
    typed: TypedMpt<AccountRlp>,
}

impl StateMpt {
    pub fn new(strategy: OnOrphanedHashNode) -> Self {
        Self {
            typed: TypedMpt {
                inner: HashedPartialTrie::new_with_strategy(Node::Empty, strategy),
                _ty: PhantomData,
            },
        }
    }
    #[deprecated = "prefer operations on `Address` where possible, as SMT support requires this"]
    pub fn insert_by_hashed_address(
        &mut self,
        key: H256,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        self.typed.insert(TrieKey::from_hash(key), account)
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
    pub fn root(&self) -> H256 {
        self.typed.root()
    }
}

impl StateTrie for StateMpt {
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        #[expect(deprecated)]
        self.insert_by_hashed_address(crate::hash(address), account)
    }
    /// Insert a deferred part of the trie
    fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) -> anyhow::Result<()> {
        self.typed.insert_hash(key, hash)
    }
    fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.typed
            .get(TrieKey::from_hash(keccak_hash::keccak(address)))
    }
    /// Delete the account at `address`, returning any remaining branch on
    /// collapse
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<TrieKey>> {
        Ok(
            crate::decoding::delete_node_and_report_remaining_key_if_branch_collapsed(
                self.typed.as_mut_hashed_partial_trie_unchecked(),
                &TrieKey::from_address(address),
            )?,
        )
    }
    fn contains_address(&self, address: Address) -> bool {
        self.typed
            .as_hashed_partial_trie()
            .contains(TrieKey::from_address(address).into_nibbles())
    }
    fn trim_to(&mut self, addresses: impl IntoIterator<Item = TrieKey>) -> anyhow::Result<()> {
        let inner = mpt_trie::trie_subsets::create_trie_subset(
            self.typed.as_hashed_partial_trie(),
            addresses.into_iter().map(TrieKey::into_nibbles),
        )?;
        self.typed = TypedMpt {
            inner,
            _ty: PhantomData,
        };
        Ok(())
    }
    fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_ {
        self.typed
            .iter()
            .map(|(key, rlp)| (key.into_hash().expect("key is always H256"), rlp))
    }
}

impl From<StateMpt> for HashedPartialTrie {
    fn from(value: StateMpt) -> Self {
        let StateMpt {
            typed: TypedMpt { inner, _ty },
        } = value;
        inner
    }
}

pub struct StateSmt {
    address2state: BTreeMap<Address, AccountRlp>,
    deferred: BTreeMap<TrieKey, H256>,
}

pub trait StateTrie {
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>>;
    fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) -> anyhow::Result<()>;
    fn get_by_address(&self, address: Address) -> Option<AccountRlp>;
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<TrieKey>>;
    fn contains_address(&self, address: Address) -> bool;
    fn trim_to(&mut self, address: impl IntoIterator<Item = TrieKey>) -> anyhow::Result<()>;
    fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_;
}

impl StateTrie for StateSmt {
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        Ok(self.address2state.insert(address, account))
    }
    fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) -> anyhow::Result<()> {
        self.deferred.insert(key, hash);
        Ok(())
    }
    fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.address2state.get(&address).copied()
    }
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<TrieKey>> {
        self.address2state.remove(&address);
        Ok(None)
    }
    fn contains_address(&self, address: Address) -> bool {
        self.address2state.contains_key(&address)
    }
    fn trim_to(&mut self, address: impl IntoIterator<Item = TrieKey>) -> anyhow::Result<()> {
        let _ = address;
        Ok(())
    }
    fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_ {
        self.address2state.iter().map(|(k, v)| (crate::hash(k), *v))
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
    pub fn insert(&mut self, key: TrieKey, value: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let prev = self.untyped.get(key.into_nibbles()).map(Vec::from);
        self.untyped.insert(key.into_nibbles(), value)?;
        Ok(prev)
    }
    pub fn insert_hash(&mut self, key: TrieKey, hash: H256) -> anyhow::Result<()> {
        self.untyped.insert(key.into_nibbles(), hash)?;
        Ok(())
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

    /// Delete the given `key`, returning any remaining branch on collapse
    pub fn reporting_remove(&mut self, key: TrieKey) -> anyhow::Result<Option<TrieKey>> {
        Ok(
            crate::decoding::delete_node_and_report_remaining_key_if_branch_collapsed(
                &mut self.untyped,
                &key,
            )?,
        )
    }
}
