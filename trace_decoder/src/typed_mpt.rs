//! Principled MPT types used in this library.

use core::fmt;
use std::{
    collections::{BTreeMap, HashSet},
    iter,
};

use anyhow::Context as _;
use copyvec::CopyVec;
use ethereum_types::{Address, H256};
use evm_arithmetization::generation::mpt::AccountRlp;
use keccak_hash::keccak;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, OnOrphanedHashNode, PartialTrie as _},
    trie_ops::ValOrHash,
};
use u4::{AsNibbles, U4};

/// Global, <code>[hash](keccak)([Address]) -> [AccountRlp]</code>.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#state-trie>
#[derive(Debug, Clone, Default)]
pub struct StateTrie {
    /// items actually in the trie
    full: BTreeMap<H256, AccountRlp>,
    deferred_subtries: BTreeMap<Nibbles, H256>,
    deferred_accounts: BTreeMap<H256, AccountRlp>,
}

impl StateTrie {
    /// Defer accounts in `locations`.
    /// Absent values are not an error.
    pub fn trim_to(&mut self, locations: impl IntoIterator<Item = H256>) {
        let want = locations.into_iter().collect::<HashSet<_>>();
        let have = self.full.keys().copied().collect();
        for hash in HashSet::difference(&have, &want) {
            let (k, v) = self.full.remove_entry(hash).expect("key is in `have`");
            self.deferred_accounts.insert(k, v);
        }
    }
    pub fn contains_address(&self, address: Address) -> bool {
        self.full.contains_key(&keccak(address))
    }
    pub fn insert_by_hashed_address(&mut self, hashed_address: H256, account: AccountRlp) {
        self.full.insert(hashed_address, account);
    }
    pub fn insert_by_address(&mut self, address: Address, account: AccountRlp) {
        self.insert_by_hashed_address(keccak(address), account)
    }
    pub fn insert_hash_by_key(&mut self, key: TrieKey, hash: H256) {
        self.deferred_subtries.insert(key.into_nibbles(), hash);
    }
    pub fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.full.get(&keccak(address)).copied()
    }
    pub fn remove_by_address(&mut self, address: Address) {
        self.full.remove(&keccak(address));
    }

    pub fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_ {
        self.full.iter().map(|(h, rlp)| (*h, *rlp))
    }
}
impl StateTrie {
    pub fn from_mpt(src: &HashedPartialTrie) -> anyhow::Result<Self> {
        let mut this = Self::default();
        for (path, voh) in src.items() {
            match voh {
                ValOrHash::Val(it) => this.insert_by_hashed_address(
                    nibbles2hash(path).context("invalid depth")?,
                    rlp::decode(&it)?,
                ),
                ValOrHash::Hash(hash) => this.insert_hash_by_key(TrieKey::from_nibbles(path), hash),
            };
        }
        Ok(this)
    }
    pub fn to_mpt(&self) -> anyhow::Result<HashedPartialTrie> {
        let Self {
            full,
            deferred_subtries,
            deferred_accounts,
        } = self;

        let mut theirs = HashedPartialTrie::default();
        for (path, hash) in deferred_subtries {
            theirs.insert(*path, *hash)?
        }
        for (haddr, acct) in full.iter().chain(deferred_accounts) {
            theirs.insert(Nibbles::from_h256_be(*haddr), rlp::encode(acct).to_vec())?;
        }
        Ok(mpt_trie::trie_subsets::create_trie_subset(
            &theirs,
            self.full.keys().map(|it| Nibbles::from_h256_be(*it)),
        )?)
    }
}

fn nibbles2hash(mut nibbles: Nibbles) -> Option<H256> {
    let mut bytes = [0; 32];

    let mut nibbles = iter::from_fn(|| match nibbles.count {
        0 => None,
        _ => Some(nibbles.pop_next_nibble_front()),
    });
    for (ix, nibble) in nibbles.by_ref().enumerate() {
        AsNibbles(&mut bytes).set(ix, U4::new(nibble)?)
    }
    match nibbles.next() {
        Some(_) => None, // too many
        None => Some(H256(bytes)),
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
}
