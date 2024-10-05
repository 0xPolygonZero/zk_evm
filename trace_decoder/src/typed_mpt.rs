//! Principled MPT types used in this library.

use core::fmt;
use std::{cmp, collections::BTreeMap, marker::PhantomData};

use anyhow::ensure;
use bitvec::{order::Msb0, slice::BitSlice, view::BitView as _};
use copyvec::CopyVec;
use either::Either;
use ethereum_types::{Address, BigEndianHash as _, H256, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::partial_trie::{HashedPartialTrie, Node, OnOrphanedHashNode, PartialTrie as _};
use u4::{AsNibbles, U4};

/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie>.
///
/// Portions of the trie may be _hashed out_: see [`Self::insert_hash`].
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
    ///
    /// See [module documentation](super) for more.
    fn insert_hash(&mut self, key: MptKey, hash: H256) -> anyhow::Result<()> {
        self.inner.insert(key.into_nibbles(), hash)?;
        Ok(())
    }
    /// Returns an [`Error`] if the `key` crosses into a part of the trie that
    /// isn't hydrated.
    fn insert(&mut self, key: MptKey, value: T) -> anyhow::Result<Option<T>>
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
    fn get(&self, key: MptKey) -> Option<T>
    where
        T: rlp::Decodable,
    {
        let bytes = self.inner.get(key.into_nibbles())?;
        Some(rlp::decode(bytes).expect(Self::PANIC_MSG))
    }
    const fn as_hashed_partial_trie(&self) -> &HashedPartialTrie {
        &self.inner
    }
    fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.inner
    }
    fn root(&self) -> H256 {
        self.inner.hash()
    }
    /// Note that this returns owned paths and items.
    fn iter(&self) -> impl Iterator<Item = (MptKey, T)> + '_
    where
        T: rlp::Decodable,
    {
        self.inner.keys().filter_map(|nib| {
            let path = MptKey::from_nibbles(nib);
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
    type Item = (MptKey, T);
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
pub struct MptKey(CopyVec<U4, 64>);

impl fmt::Display for MptKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for u in self.0 {
            f.write_fmt(format_args!("{:x}", u))?
        }
        Ok(())
    }
}

impl MptKey {
    pub fn new(components: impl IntoIterator<Item = U4>) -> anyhow::Result<Self> {
        Ok(MptKey(CopyVec::try_from_iter(components)?))
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
    pub fn from_slot_position(pos: U256) -> Self {
        let mut bytes = [0; 32];
        pos.to_big_endian(&mut bytes);
        Self::from_hash(keccak_hash::keccak(H256::from_slice(&bytes)))
    }
    pub fn from_hash(H256(bytes): H256) -> Self {
        Self::new(AsNibbles(bytes)).expect("32 bytes is 64 nibbles, which fits")
    }

    pub fn from_txn_ix(txn_ix: usize) -> Self {
        MptKey::new(AsNibbles(rlp::encode(&txn_ix))).expect(
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
    fn into_bits(self) -> smt_trie::bits::Bits {
        let mut bits = smt_trie::bits::Bits::default();
        for component in self.0 {
            let byte = component as u8;
            // the four high bits are zero
            for bit in byte.view_bits::<Msb0>().into_iter().by_vals().skip(4) {
                bits.push_bit(bit);
            }
        }
        bits
    }

    pub fn into_hash(self) -> Option<H256> {
        let Self(nibbles) = self;
        let mut bytes = [0; 32];
        AsNibbles(&mut bytes).pack_from_slice(&nibbles.into_array()?);
        Some(H256(bytes))
    }
}

impl From<Address> for MptKey {
    fn from(value: Address) -> Self {
        Self::from_hash(keccak_hash::keccak(value))
    }
}

#[test]
fn mpt_key_into_hash() {
    assert_eq!(MptKey::new([]).unwrap().into_hash(), None);
    assert_eq!(
        MptKey::new(itertools::repeat_n(u4::u4!(0), 64))
            .unwrap()
            .into_hash(),
        Some(H256::zero())
    )
}

/// Bounded sequence of bits,
/// used as a key for [`StateSmt`].
///
/// Semantically equivalent to
#[derive(Clone, Copy)]
pub struct SmtKey {
    bits: bitvec::array::BitArray<[u8; 32]>,
    len: usize,
}

impl SmtKey {
    fn as_bitslice(&self) -> &BitSlice<u8> {
        self.bits.as_bitslice().get(..self.len).unwrap()
    }
}

impl fmt::Debug for SmtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.as_bitslice().iter().map(|it| match *it {
                true => 1,
                false => 0,
            }))
            .finish()
    }
}

impl fmt::Display for SmtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for bit in self.as_bitslice() {
            f.write_str(match *bit {
                true => "1",
                false => "0",
            })?
        }
        Ok(())
    }
}

impl SmtKey {
    pub fn new(components: impl IntoIterator<Item = bool>) -> anyhow::Result<Self> {
        let mut bits = bitvec::array::BitArray::default();
        let mut len = 0;
        for (ix, bit) in components.into_iter().enumerate() {
            ensure!(
                bits.get(ix).is_some(),
                "expected at most {} components",
                bits.len()
            );
            bits.set(ix, bit);
            len += 1
        }
        Ok(Self { bits, len })
    }
}

impl From<Address> for SmtKey {
    fn from(value: Address) -> Self {
        todo!()
    }
}

impl Ord for SmtKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_bitslice().cmp(other.as_bitslice())
    }
}
impl PartialOrd for SmtKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.as_bitslice().partial_cmp(other.as_bitslice())
    }
}
impl Eq for SmtKey {}
impl PartialEq for SmtKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bitslice().eq(other.as_bitslice())
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
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, txn_ix: usize, val: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let prev = self
            .untyped
            .get(MptKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(MptKey::from_txn_ix(txn_ix).into_nibbles(), val)?;
        Ok(prev)
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub const fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        &self.untyped
    }
    /// _Hash out_ parts of the trie that aren't in `txn_ixs`.
    pub fn mask(&mut self, txn_ixs: impl IntoIterator<Item = usize>) -> anyhow::Result<()> {
        self.untyped = mpt_trie::trie_subsets::create_trie_subset(
            &self.untyped,
            txn_ixs
                .into_iter()
                .map(|it| MptKey::from_txn_ix(it).into_nibbles()),
        )?;
        Ok(())
    }
}

impl From<TransactionTrie> for HashedPartialTrie {
    fn from(value: TransactionTrie) -> Self {
        value.untyped
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
            .get(MptKey::from_txn_ix(txn_ix).into_nibbles())
            .map(Vec::from);
        self.untyped
            .insert(MptKey::from_txn_ix(txn_ix).into_nibbles(), val)?;
        Ok(prev)
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub const fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        &self.untyped
    }
    /// _Hash out_ parts of the trie that aren't in `txn_ixs`.
    pub fn mask(&mut self, txn_ixs: impl IntoIterator<Item = usize>) -> anyhow::Result<()> {
        self.untyped = mpt_trie::trie_subsets::create_trie_subset(
            &self.untyped,
            txn_ixs
                .into_iter()
                .map(|it| MptKey::from_txn_ix(it).into_nibbles()),
        )?;
        Ok(())
    }
}

impl From<ReceiptTrie> for HashedPartialTrie {
    fn from(value: ReceiptTrie) -> Self {
        value.untyped
    }
}

/// TODO(0xaatif): document this after refactoring is done https://github.com/0xPolygonZero/zk_evm/issues/275
pub trait StateTrie {
    type Key;
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>>;
    fn get_by_address(&self, address: Address) -> Option<AccountRlp>;
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<Self::Key>>;
    /// _Hash out_ parts of the trie that aren't in `txn_ixs`.
    fn mask(&mut self, address: impl IntoIterator<Item = Self::Key>) -> anyhow::Result<()>;
    fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_;
    fn root(&self) -> H256;
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
    /// Insert a _hashed out_ part of the trie
    pub fn insert_hash_by_key(&mut self, key: MptKey, hash: H256) -> anyhow::Result<()> {
        self.typed.insert_hash(key, hash)
    }
    #[deprecated = "prefer operations on `Address` where possible, as SMT support requires this"]
    pub fn insert_by_hashed_address(
        &mut self,
        key: H256,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        self.typed.insert(MptKey::from_hash(key), account)
    }
    pub fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_ {
        self.typed
            .iter()
            .map(|(key, rlp)| (key.into_hash().expect("key is always H256"), rlp))
    }
    pub fn as_hashed_partial_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        self.typed.as_hashed_partial_trie()
    }
}

impl StateTrie for StateMpt {
    type Key = MptKey;
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        #[expect(deprecated)]
        self.insert_by_hashed_address(keccak_hash::keccak(address), account)
    }
    fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.typed
            .get(MptKey::from_hash(keccak_hash::keccak(address)))
    }
    /// Delete the account at `address`, returning any remaining branch on
    /// collapse
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<MptKey>> {
        delete_node_and_report_remaining_key_if_branch_collapsed(
            self.typed.as_mut_hashed_partial_trie_unchecked(),
            MptKey::from_address(address),
        )
    }
    fn mask(&mut self, addresses: impl IntoIterator<Item = MptKey>) -> anyhow::Result<()> {
        let inner = mpt_trie::trie_subsets::create_trie_subset(
            self.typed.as_hashed_partial_trie(),
            addresses.into_iter().map(MptKey::into_nibbles),
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
    fn root(&self) -> H256 {
        self.typed.root()
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

// TODO(0xaatif): trackme
// We're covering for [`smt_trie`] in a couple of ways:
// - insertion operations aren't fallible, they just panic.
// - it documents a requirement that `set_hash` is called before `set`.
#[derive(Clone, Debug)]
pub struct StateSmt {
    address2state: BTreeMap<Address, AccountRlp>,
    hashed_out: BTreeMap<MptKey, H256>,
}

impl StateTrie for StateSmt {
    type Key = SmtKey;
    fn insert_by_address(
        &mut self,
        address: Address,
        account: AccountRlp,
    ) -> anyhow::Result<Option<AccountRlp>> {
        Ok(self.address2state.insert(address, account))
    }
    fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.address2state.get(&address).copied()
    }
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<SmtKey>> {
        self.address2state.remove(&address);
        Ok(None)
    }
    fn mask(&mut self, address: impl IntoIterator<Item = SmtKey>) -> anyhow::Result<()> {
        let _ = address;
        Ok(())
    }
    fn iter(&self) -> impl Iterator<Item = (H256, AccountRlp)> + '_ {
        self.address2state
            .iter()
            .map(|(addr, acct)| (keccak_hash::keccak(addr), *acct))
    }
    fn root(&self) -> H256 {
        conv_hash::smt2eth(self.as_smt().root)
    }
}

impl StateSmt {
    fn as_smt(&self) -> smt_trie::smt::Smt<smt_trie::db::MemoryDb> {
        let Self {
            address2state,
            hashed_out,
        } = self;
        let mut smt = smt_trie::smt::Smt::<smt_trie::db::MemoryDb>::default();
        for (k, v) in hashed_out {
            smt.set_hash(k.into_bits(), conv_hash::eth2smt(*v));
        }
        for (
            addr,
            AccountRlp {
                nonce,
                balance,
                storage_root,
                code_hash,
            },
        ) in address2state
        {
            smt.set(smt_trie::keys::key_nonce(*addr), *nonce);
            smt.set(smt_trie::keys::key_balance(*addr), *balance);
            smt.set(smt_trie::keys::key_code(*addr), code_hash.into_uint());
            smt.set(
                // REVIEW(0xaatif): I don't know what to do here
                smt_trie::keys::key_storage(*addr, U256::zero()),
                storage_root.into_uint(),
            );
        }
        smt
    }
}

mod conv_hash {
    use std::array;

    use ethereum_types::H256;
    use itertools::Itertools as _;
    use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

    pub fn eth2smt(H256(bytes): H256) -> smt_trie::smt::HashOut {
        let mut bytes = bytes.into_iter();
        // (no unsafe, no unstable)
        let ret = HashOut {
            elements: array::from_fn(|_ix| {
                let (a, b, c, d, e, f, g, h) = bytes.next_tuple().unwrap();
                // REVIEW(0xaatif): what endianness?
                GoldilocksField(u64::from_be_bytes([a, b, c, d, e, f, g, h]))
            }),
        };
        assert_eq!(bytes.len(), 0);
        ret
    }
    pub fn smt2eth(HashOut { elements }: smt_trie::smt::HashOut) -> H256 {
        H256(
            build_array::ArrayBuilder::from_iter(
                elements
                    .into_iter()
                    .flat_map(|GoldilocksField(u)| u.to_be_bytes()),
            )
            .build_exact()
            .unwrap(),
        )
    }

    #[test]
    fn test() {
        for h in [
            H256::zero(),
            H256(array::from_fn(|ix| ix as u8)),
            H256([u8::MAX; 32]),
        ] {
            assert_eq!(smt2eth(eth2smt(h)), h);
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
    pub fn get(&mut self, key: &MptKey) -> Option<&[u8]> {
        self.untyped.get(key.into_nibbles())
    }
    pub fn insert(&mut self, key: MptKey, value: Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let prev = self.get(&key).map(Vec::from);
        self.untyped.insert(key.into_nibbles(), value)?;
        Ok(prev)
    }
    pub fn insert_hash(&mut self, key: MptKey, hash: H256) -> anyhow::Result<()> {
        self.untyped.insert(key.into_nibbles(), hash)?;
        Ok(())
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    pub const fn as_hashed_partial_trie(&self) -> &HashedPartialTrie {
        &self.untyped
    }
    pub fn reporting_remove(&mut self, key: MptKey) -> anyhow::Result<Option<MptKey>> {
        delete_node_and_report_remaining_key_if_branch_collapsed(&mut self.untyped, key)
    }
    pub fn as_mut_hashed_partial_trie_unchecked(&mut self) -> &mut HashedPartialTrie {
        &mut self.untyped
    }
    /// _Hash out_ the parts of the trie that aren't in `paths`.
    pub fn mask(&mut self, paths: impl IntoIterator<Item = MptKey>) -> anyhow::Result<()> {
        self.untyped = mpt_trie::trie_subsets::create_trie_subset(
            &self.untyped,
            paths.into_iter().map(MptKey::into_nibbles),
        )?;
        Ok(())
    }
}

impl From<StorageTrie> for HashedPartialTrie {
    fn from(value: StorageTrie) -> Self {
        value.untyped
    }
}

/// If a branch collapse occurred after a delete, then we must ensure that
/// the other single child that remains also is not hashed when passed into
/// plonky2. Returns the key to the remaining child if a collapse occurred.
fn delete_node_and_report_remaining_key_if_branch_collapsed(
    trie: &mut HashedPartialTrie,
    key: MptKey,
) -> anyhow::Result<Option<MptKey>> {
    let old_trace = get_trie_trace(trie, key);
    trie.delete(key.into_nibbles())?;
    let new_trace = get_trie_trace(trie, key);
    Ok(
        node_deletion_resulted_in_a_branch_collapse(&old_trace, &new_trace)
            .map(MptKey::from_nibbles),
    )
}

fn get_trie_trace(trie: &HashedPartialTrie, k: MptKey) -> mpt_trie::utils::TriePath {
    mpt_trie::special_query::path_for_query(trie, k.into_nibbles(), true).collect()
}

/// Comparing the path of the deleted key before and after the deletion,
/// determine if the deletion resulted in a branch collapsing into a leaf or
/// extension node, and return the path to the remaining child if this
/// occurred.
fn node_deletion_resulted_in_a_branch_collapse(
    old_path: &mpt_trie::utils::TriePath,
    new_path: &mpt_trie::utils::TriePath,
) -> Option<mpt_trie::nibbles::Nibbles> {
    // Collapse requires at least 2 nodes.
    if old_path.0.len() < 2 {
        return None;
    }

    // If the node path length decreased after the delete, then a collapse occurred.
    // As an aside, note that while it's true that the branch could have collapsed
    // into an extension node with multiple nodes below it, the query logic will
    // always stop at most one node after the keys diverge, which guarantees that
    // the new trie path will always be shorter if a collapse occurred.
    let branch_collapse_occurred = old_path.0.len() > new_path.0.len();

    // Now we need to determine the key of the only remaining node after the
    // collapse.
    branch_collapse_occurred.then(|| mpt_trie::utils::IntoTrieKey::into_key(new_path.iter()))
}
