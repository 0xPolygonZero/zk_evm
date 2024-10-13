//! Principled trie types and abstractions used in this library.

use std::{
    cmp,
    collections::{BTreeMap, HashSet},
    fmt,
    marker::PhantomData,
};

use alloy_compat::Compat as _;
use anyhow::{ensure, Context as _};
use bitvec::slice::BitSlice;
use copyvec::CopyVec;
use ethereum_types::{Address, BigEndianHash as _, H256, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use mpt_trie::{
    partial_trie::{HashedPartialTrie, Node, OnOrphanedHashNode, PartialTrie as _},
    trie_ops::ValOrHash,
};
use u4::{AsNibbles, U4};

pub type Type1Account = AccountRlp;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Type2Account {
    pub balance: U256,
    pub nonce: U256,
    pub code: U256,
    pub code_length: U256,
    pub storage: BTreeMap<U256, U256>,
}

pub trait Account {
    fn balance(&self) -> U256;
    fn balance_mut(&mut self) -> &mut U256;
    fn nonce(&self) -> U256;
    fn nonce_mut(&mut self) -> &mut U256;
    fn set_code(&mut self, hash: H256);
    fn set_code_length(&mut self, length: Option<U256>);
}

impl Account for Type1Account {
    fn balance(&self) -> U256 {
        self.balance
    }
    fn balance_mut(&mut self) -> &mut U256 {
        &mut self.balance
    }
    fn nonce(&self) -> U256 {
        self.nonce
    }
    fn nonce_mut(&mut self) -> &mut U256 {
        &mut self.nonce
    }
    fn set_code(&mut self, hash: H256) {
        self.code_hash = hash
    }
    fn set_code_length(&mut self, length: Option<U256>) {
        let _ = length;
    }
}
impl Account for Type2Account {
    fn balance(&self) -> U256 {
        self.balance
    }
    fn balance_mut(&mut self) -> &mut U256 {
        &mut self.balance
    }
    fn nonce(&self) -> U256 {
        self.nonce
    }
    fn nonce_mut(&mut self) -> &mut U256 {
        &mut self.nonce
    }
    fn set_code(&mut self, hash: H256) {
        self.code = hash.into_uint()
    }
    fn set_code_length(&mut self, length: Option<U256>) {
        if let Some(length) = length {
            self.code_length = length
        }
    }
}
/// A Merkle PATRICIA Trie, where the values are always [RLP](rlp)-encoded `T`s.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie>.
///
/// Portions of the trie may be _hashed out_: see [`Self::insert_hash_by_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedMpt<T> {
    inner: HashedPartialTrie,
    _ty: PhantomData<fn() -> T>,
}

impl<T> TypedMpt<T> {
    const PANIC_MSG: &str = "T encoding/decoding should round-trip,\
    and only encoded `T`s are ever inserted";
    fn new() -> Self {
        Self {
            inner: HashedPartialTrie::new_with_strategy(
                Node::Empty,
                // These are used in the Type1World, which requires this behaviour.
                OnOrphanedHashNode::CollapseToExtension,
            ),
            _ty: PhantomData,
        }
    }
    /// Insert a node which represents an out-of-band sub-trie.
    ///
    /// See [module documentation](super) for more.
    pub fn insert_hash_by_key(&mut self, key: MptKey, hash: H256) -> anyhow::Result<()> {
        self.inner.insert(key.into_nibbles(), hash)?;
        Ok(())
    }
    /// Returns [`Err`] if the `key` crosses into a part of the trie that
    /// is hashed out.
    pub fn insert_value_by_key(&mut self, key: MptKey, value: T) -> anyhow::Result<()>
    where
        T: rlp::Encodable + rlp::Decodable,
    {
        self.inner
            .insert(key.into_nibbles(), rlp::encode(&value).to_vec())?;
        Ok(())
    }
    /// Note that this returns [`None`] if `key` crosses into a part of the
    /// trie that is hashed out.
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
    pub fn root(&self) -> H256 {
        self.inner.hash()
    }
    /// Note that this returns owned paths and items.
    #[cfg(test)]
    pub fn iter(&self) -> impl Iterator<Item = (MptKey, T)> + '_
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

impl<T> From<TypedMpt<T>> for HashedPartialTrie {
    fn from(value: TypedMpt<T>) -> Self {
        value.inner
    }
}

/// Bounded sequence of [`U4`],
/// used as a key for [`TypedMpt`] and [`Type1World`].
///
/// Semantically equivalent to [`mpt_trie::nibbles::Nibbles`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MptKey(CopyVec<U4, 64>);

impl fmt::Display for MptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    pub fn into_hash(self) -> Option<H256> {
        let Self(nibbles) = self;
        let mut bytes = [0; 32];
        AsNibbles(&mut bytes).pack_from_slice(&nibbles.into_array()?);
        Some(H256(bytes))
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
/// used as a key for [`Type2World`].
///
/// Semantically equivalent to [`smt_trie::bits::Bits`].
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

    pub fn into_smt_bits(self) -> smt_trie::bits::Bits {
        let mut bits = smt_trie::bits::Bits::default();
        for bit in self.as_bitslice() {
            bits.push_bit(*bit)
        }
        bits
    }
}

impl Ord for SmtKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_bitslice().cmp(other.as_bitslice())
    }
}
impl PartialOrd for SmtKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
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
    pub fn insert_value_by_index(
        &mut self,
        txn_ix: usize,
        val: Vec<u8>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
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

/// [`World::Key`]-agnostic operations.
pub trait Key {
    fn from_address(address: Address) -> Self;
    fn from_hash(hash: H256) -> Self;
    fn from_slot_position(ix: U256) -> Self;
}

impl Key for SmtKey {
    fn from_hash(hash: H256) -> Self {
        let _ = hash;
        todo!()
    }
    fn from_slot_position(ix: U256) -> Self {
        let _ = ix;
        todo!()
    }

    fn from_address(address: Address) -> Self {
        let _ = address;
        todo!()
    }
}

impl Key for MptKey {
    fn from_hash(hash: H256) -> Self {
        let H256(bytes) = hash;
        Self::new(AsNibbles(bytes)).expect("32 bytes is 64 nibbles, which fits")
    }

    fn from_slot_position(ix: U256) -> Self {
        let mut bytes = [0; 32];
        ix.to_big_endian(&mut bytes);
        Self::from_hash(keccak_hash::keccak(H256::from_slice(&bytes)))
    }

    fn from_address(address: Address) -> Self {
        Self::from_hash(keccak_hash::keccak(address))
    }
}

/// The state and storage of all accounts.
///
/// Some parts of the tries may be _hashed out_.
pub trait World {
    type Key;
    type Account;
    fn insert_account_info(
        &mut self,
        address: Address,
        account: Self::Account,
    ) -> anyhow::Result<()>;
    fn get_account_info(&self, address: Address) -> Option<Self::Account>;
    /// Workaround MPT quirks.
    fn reporting_remove_account_info(
        &mut self,
        address: Address,
    ) -> anyhow::Result<Option<Self::Key>>;
    /// _Hash out_ parts of the (state) trie that aren't in `addresses`.
    fn mask_accounts(
        &mut self,
        addresses: impl IntoIterator<Item = Self::Key>,
    ) -> anyhow::Result<()>;
    fn root(&self) -> H256;
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()>;
    fn store_hash(&mut self, address: Address, position: H256, value: H256) -> anyhow::Result<()>;
    fn load_int(&self, address: Address, slot: U256) -> anyhow::Result<U256>;
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()>;
    fn reporting_remove_storage(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<Self::Key>>;
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()>;
    fn retain_storage(
        &mut self,
        addresses: impl IntoIterator<Item = Address>,
    ) -> anyhow::Result<()>;
    fn mask_storage(
        &mut self,
        address: Address,
        keys: impl IntoIterator<Item = Self::Key>,
    ) -> anyhow::Result<()>;
}

/// State and storage based on distinct [MPTs](HashedPartialTrie).
#[derive(Debug, Clone, Default)]
pub struct Type1World {
    pub state: TypedMpt<AccountRlp>,
    pub storage: BTreeMap<H256, StorageTrie>,
}

impl Type1World {
    pub fn new(
        state: HashedPartialTrie,
        storage: impl IntoIterator<Item = (H256, HashedPartialTrie)>,
    ) -> anyhow::Result<Self> {
        let mut storage = storage
            .into_iter()
            .map(|(k, v)| (k, StorageTrie::from(v)))
            .collect::<BTreeMap<_, _>>();
        let mut typed = TypedMpt::default();
        for (key, vorh) in state.items() {
            let key = MptKey::from_nibbles(key);
            match vorh {
                ValOrHash::Val(vec) => {
                    let haddr = key.into_hash().context("invalid key length")?;
                    let acct = rlp::decode::<AccountRlp>(&vec)?;
                    let storage = storage.entry(haddr).or_insert_with(|| {
                        HashedPartialTrie::new_with_strategy(
                            Node::Hash(acct.storage_root),
                            OnOrphanedHashNode::CollapseToExtension,
                        )
                        .into()
                    });
                    ensure!(storage.root() == acct.storage_root);
                    typed.insert_value_by_key(key, acct)?
                }
                ValOrHash::Hash(h256) => typed.insert_hash_by_key(key, h256)?,
            }
        }
        Ok(Self {
            state: typed,
            storage,
        })
    }
}

impl World for Type1World {
    type Key = MptKey;
    type Account = AccountRlp;
    fn insert_account_info(&mut self, address: Address, account: AccountRlp) -> anyhow::Result<()> {
        let key = keccak_hash::keccak(address);
        self.state
            .insert_value_by_key(MptKey::from_hash(key), account)
    }
    fn get_account_info(&self, address: Address) -> Option<AccountRlp> {
        self.state
            .get(MptKey::from_hash(keccak_hash::keccak(address)))
    }
    /// Delete the account at `address`, returning any remaining branch on
    /// collapse
    fn reporting_remove_account_info(
        &mut self,
        address: Address,
    ) -> anyhow::Result<Option<MptKey>> {
        delete_node_and_report_remaining_key_if_branch_collapsed(
            self.state.as_mut_hashed_partial_trie_unchecked(),
            MptKey::from_address(address),
        )
    }
    fn mask_accounts(&mut self, addresses: impl IntoIterator<Item = MptKey>) -> anyhow::Result<()> {
        let inner = mpt_trie::trie_subsets::create_trie_subset(
            self.state.as_hashed_partial_trie(),
            addresses.into_iter().map(MptKey::into_nibbles),
        )?;
        self.state = TypedMpt {
            inner,
            _ty: PhantomData,
        };
        Ok(())
    }
    fn root(&self) -> H256 {
        self.state.root()
    }
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()> {
        on_storage_trie(self, address, |storage| {
            storage.store_int_at_slot(slot, value)
        })
    }
    fn load_int(&self, address: Address, slot: U256) -> anyhow::Result<U256> {
        self.storage
            .get(&keccak_hash::keccak(address))
            .context("storage for address")?
            .load_int(MptKey::from_slot_position(slot))
    }
    fn store_hash(&mut self, address: Address, position: H256, value: H256) -> anyhow::Result<()> {
        on_storage_trie(self, address, |storage| {
            storage.store_hash(MptKey::from_hash(position), value)
        })
    }
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let clobbered = self
            .storage
            .insert(keccak_hash::keccak(address), StorageTrie::default());
        if clobbered.is_some() {
            log::warn!("clobbered storage for {address:x}")
        }
        Ok(())
    }
    fn reporting_remove_storage(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<Self::Key>> {
        let mut account = self.get_account_info(address).context("no such account")?;
        let storage = self
            .storage
            .get_mut(&keccak_hash::keccak(address))
            .context("no such account")?;
        let report = storage.reporting_remove(MptKey::from_slot_position(slot))?;
        account.storage_root = storage.root();
        self.insert_account_info(address, account)?;
        Ok(report)
    }
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let removed = self.storage.remove(&keccak_hash::keccak(address));
        ensure!(removed.is_some());
        Ok(())
    }
    fn retain_storage(
        &mut self,
        addresses: impl IntoIterator<Item = Address>,
    ) -> anyhow::Result<()> {
        let haddrs = addresses
            .into_iter()
            .map(keccak_hash::keccak)
            .collect::<HashSet<_>>();
        self.storage.retain(|haddr, _| haddrs.contains(haddr));
        Ok(())
    }
    fn mask_storage(
        &mut self,
        address: Address,
        keys: impl IntoIterator<Item = Self::Key>,
    ) -> anyhow::Result<()> {
        if let Some(storage) = self.storage.get_mut(&keccak_hash::keccak(address)) {
            storage.mask(keys)?;
        }
        Ok(())
    }
}

/// Update the [`AccountRlp::storage_root`] after running `f`.
fn on_storage_trie(
    world: &mut Type1World,
    address: Address,
    f: impl FnOnce(&mut StorageTrie) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut account = world.get_account_info(address).context("no such account")?;
    let storage = world
        .storage
        .entry(keccak_hash::keccak(address))
        .or_default();
    f(storage)?;
    account.storage_root = storage.root();
    world.insert_account_info(address, account)
}

impl From<Type1World> for HashedPartialTrie {
    fn from(value: Type1World) -> Self {
        let Type1World {
            state: TypedMpt { inner, _ty },
            storage: _,
        } = value;
        inner
    }
}

// TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/706
// We're covering for [`smt_trie`] in a couple of ways:
// - insertion operations aren't fallible, they just panic.
// - it documents a requirement that `set_hash` is called before `set`.
#[derive(Clone, Debug)]
pub struct Type2World {
    address2state: BTreeMap<Address, Type2Account>,
    hashed_out: BTreeMap<SmtKey, H256>,
}

impl World for Type2World {
    type Key = SmtKey;
    type Account = Type2Account;
    fn insert_account_info(
        &mut self,
        address: Address,
        account: Type2Account,
    ) -> anyhow::Result<()> {
        self.address2state.insert(address, account);
        Ok(())
    }
    fn get_account_info(&self, address: Address) -> Option<Type2Account> {
        self.address2state.get(&address).cloned()
    }
    fn reporting_remove_account_info(
        &mut self,
        address: Address,
    ) -> anyhow::Result<Option<SmtKey>> {
        self.address2state.remove(&address);
        Ok(None)
    }
    fn mask_accounts(&mut self, address: impl IntoIterator<Item = SmtKey>) -> anyhow::Result<()> {
        let _ = address;
        Ok(())
    }
    fn root(&self) -> H256 {
        conv_hash::smt2eth(self.as_smt().root)
    }
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()> {
        let _ = (address, slot, value);
        todo!()
    }
    fn load_int(&self, address: Address, slot: U256) -> anyhow::Result<U256> {
        let _ = (address, slot);
        todo!()
    }
    fn store_hash(&mut self, address: Address, position: H256, value: H256) -> anyhow::Result<()> {
        let _ = (address, position, value);
        todo!()
    }
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let _ = address;
        todo!()
    }
    fn reporting_remove_storage(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<SmtKey>> {
        let _ = (address, slot);
        todo!()
    }
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let _ = address;
        todo!()
    }
    fn retain_storage(
        &mut self,
        addresses: impl IntoIterator<Item = Address>,
    ) -> anyhow::Result<()> {
        let _ = addresses;
        todo!()
    }

    fn mask_storage(
        &mut self,
        address: Address,
        keys: impl IntoIterator<Item = Self::Key>,
    ) -> anyhow::Result<()> {
        let _ = (address, keys);
        todo!()
    }
}

impl Type2World {
    pub(crate) fn new_unchecked(
        address2state: BTreeMap<Address, Type2Account>,
        hashed_out: BTreeMap<SmtKey, H256>,
    ) -> Self {
        Self {
            address2state,
            hashed_out,
        }
    }

    fn as_smt(&self) -> smt_trie::smt::Smt<smt_trie::db::MemoryDb> {
        let Self {
            address2state,
            hashed_out,
        } = self;
        let mut smt = smt_trie::smt::Smt::<smt_trie::db::MemoryDb>::default();
        for (k, v) in hashed_out {
            smt.set_hash(k.into_smt_bits(), conv_hash::eth2smt(*v));
        }
        for (
            addr,
            Type2Account {
                balance,
                nonce,
                code,
                code_length,
                storage,
            },
        ) in address2state
        {
            smt.set(smt_trie::keys::key_nonce(*addr), *nonce);
            smt.set(smt_trie::keys::key_balance(*addr), *balance);
            smt.set(smt_trie::keys::key_code(*addr), *code);
            smt.set(smt_trie::keys::key_code_length(*addr), *code_length);
            for (slot, val) in storage {
                smt.set(smt_trie::keys::key_storage(*addr, *slot), *val);
            }
        }
        smt
    }
}

mod conv_hash {
    //! We [`u64::to_le_bytes`] because:
    //! - Reference go code just puns the bytes: <https://github.com/gateway-fm/vectorized-poseidon-gold/blob/7640564fa7d5ed93c829b156a83cb11cef744586/src/vectorizedposeidongold/vectorizedposeidongold_fallback.go#L39-L45>
    //! - It's better to fix the endianness for correctness.
    //! - Most (consumer) CPUs are little-endian.

    use std::array;

    use ethereum_types::H256;
    use itertools::Itertools as _;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field as _, PrimeField64},
        },
        hash::hash_types::HashOut,
    };

    /// # Panics
    /// - On certain inputs if `debug_assertions` are enabled. See
    ///   [`GoldilocksField::from_canonical_u64`] for more.
    pub fn eth2smt(H256(bytes): H256) -> smt_trie::smt::HashOut {
        let mut bytes = bytes.into_iter();
        // (no unsafe, no unstable)
        let ret = HashOut {
            elements: array::from_fn(|_ix| {
                let (a, b, c, d, e, f, g, h) = bytes.next_tuple().unwrap();
                GoldilocksField::from_canonical_u64(u64::from_le_bytes([a, b, c, d, e, f, g, h]))
            }),
        };
        assert_eq!(bytes.len(), 0);
        ret
    }
    pub fn smt2eth(HashOut { elements }: smt_trie::smt::HashOut) -> H256 {
        H256(
            build_array::ArrayBuilder::from_iter(
                elements
                    .iter()
                    .map(GoldilocksField::to_canonical_u64)
                    .flat_map(u64::to_le_bytes),
            )
            .build_exact()
            .unwrap(),
        )
    }

    #[test]
    fn test() {
        use plonky2::field::types::Field64 as _;
        let mut max = std::iter::repeat(GoldilocksField::ORDER - 1).flat_map(u64::to_le_bytes);
        for h in [
            H256::zero(),
            H256(array::from_fn(|ix| ix as u8)),
            H256(array::from_fn(|_| max.next().unwrap())),
        ] {
            assert_eq!(smt2eth(eth2smt(h)), h);
        }
    }
}

/// Global, per-account.
///
/// See <https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/#storage-trie>
#[derive(Debug, Clone)]
pub struct StorageTrie {
    untyped: HashedPartialTrie,
}
impl StorageTrie {
    pub fn new() -> Self {
        Self {
            untyped: HashedPartialTrie::new_with_strategy(
                Node::Empty,
                OnOrphanedHashNode::CollapseToExtension,
            ),
        }
    }
    fn load_int(&self, key: MptKey) -> anyhow::Result<U256> {
        let bytes = self.untyped.get(key.into_nibbles()).context("no item")?;
        Ok(rlp::decode(bytes)?)
    }
    fn store_int_at_slot(&mut self, slot: U256, value: U256) -> anyhow::Result<()> {
        self.untyped.insert(
            MptKey::from_slot_position(slot).into_nibbles(),
            alloy::rlp::encode(value.compat()),
        )?;
        Ok(())
    }
    fn store_hash(&mut self, key: MptKey, value: H256) -> anyhow::Result<()> {
        self.untyped
            .insert(key.into_nibbles(), alloy::rlp::encode(value.compat()))?;
        Ok(())
    }
    pub fn insert_value(&mut self, key: MptKey, value: Vec<u8>) -> anyhow::Result<()> {
        self.untyped.insert(key.into_nibbles(), value)?;
        Ok(())
    }
    pub fn insert_hash(&mut self, key: MptKey, hash: H256) -> anyhow::Result<()> {
        self.untyped.insert(key.into_nibbles(), hash)?;
        Ok(())
    }
    pub fn root(&self) -> H256 {
        self.untyped.hash()
    }
    fn reporting_remove(&mut self, key: MptKey) -> anyhow::Result<Option<MptKey>> {
        delete_node_and_report_remaining_key_if_branch_collapsed(&mut self.untyped, key)
    }
    /// _Hash out_ the parts of the trie that aren't in `paths`.
    fn mask(&mut self, paths: impl IntoIterator<Item = MptKey>) -> anyhow::Result<()> {
        self.untyped = mpt_trie::trie_subsets::create_trie_subset(
            &self.untyped,
            paths.into_iter().map(MptKey::into_nibbles),
        )?;
        Ok(())
    }
}

impl Default for StorageTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl From<HashedPartialTrie> for StorageTrie {
    fn from(untyped: HashedPartialTrie) -> Self {
        Self { untyped }
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
