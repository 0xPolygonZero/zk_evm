use std::collections::{BTreeMap, BTreeSet};

use alloy_compat::Compat as _;
use anyhow::{ensure, Context as _};
use either::Either;
use ethereum_types::{Address, BigEndianHash as _, U256};
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};
use smt_trie::code::hash_bytecode_h256;

use crate::tries::{MptKey, SmtKey, StateMpt, StorageTrie};

/// Utility trait to leverage a specific hash function across Type1 and Type2
/// zkEVM variants.
pub trait Hasher {
    fn hash(bytes: &[u8]) -> H256;
}

pub struct PoseidonHash;
pub struct KeccakHash;

impl Hasher for PoseidonHash {
    fn hash(bytes: &[u8]) -> H256 {
        hash_bytecode_h256(bytes)
    }
}

impl Hasher for KeccakHash {
    fn hash(bytes: &[u8]) -> H256 {
        keccak_hash::keccak(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateWorld {
    pub state: Either<Type1World, Type2World>,
}

impl Default for StateWorld {
    fn default() -> Self {
        if cfg!(feature = "cdk_erigon") {
            StateWorld {
                state: Either::Right(Type2World::default()),
            }
        } else {
            StateWorld {
                state: Either::Left(Type1World::default()),
            }
        }
    }
}

/// The `core` module of the `trace_decoder` crate is agnostic over state and
/// storage representations.
///
/// This is the common interface to those data structures.
pub trait World {
    /// (State) subtries may be _hashed out.
    /// This type is a key which may identify a subtrie.
    type SubtriePath;

    /// Hasher to use for contract bytecode.
    type CodeHasher: Hasher;

    //////////////////////
    /// Account operations
    //////////////////////

    /// Whether the state contains an account at the given address.
    ///
    /// `false` is not necessarily definitive - the address may belong to a
    /// _hashed out_ subtrie.
    fn contains(&mut self, address: Address) -> anyhow::Result<bool>;

    /// Update the balance for the account at the given address.
    ///
    /// Creates a new account at `address` if it does not exist.
    fn update_balance(&mut self, address: Address, f: impl FnOnce(&mut U256))
        -> anyhow::Result<()>;

    /// Update the nonce for the account at the given address.
    ///
    /// Creates a new account at `address` if it does not exist.
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()>;

    /// Hash the provided code with this `World`'s [`CodeHasher`].
    fn hash_code(&self, code: &[u8]) -> H256 {
        Self::CodeHasher::hash(code)
    }

    /// Update the code for the account at the given address.
    ///
    /// Creates a new account at `address` if it does not exist.
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()>;

    /// Update the code and code length for the account at the give address.
    ///
    /// Creates a new account at `address` if it does not exist.
    fn set_code_and_hash(
        &mut self,
        address: Address,
        code: Either<H256, U256>,
        code_length: Option<U256>,
    );
    /// The `core` module of the `trace_decoder` crate tracks required subtries
    /// for proving.
    ///
    /// In case of a state delete, it may be that certain parts of the subtrie
    /// must be retained. If so, it will be returned as [`Some`].
    fn reporting_destroy(&mut self, address: Address) -> anyhow::Result<Option<Self::SubtriePath>>;

    //////////////////////
    /// Storage operations
    //////////////////////

    /// Create an account at the given address.
    ///
    /// It may not be an error if the address already exists.
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()>;

    /// Destroy storage for the given address' account.
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()>;

    /// Store an integer for the given account at the given `slot`.
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()>;
    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()>;

    /// Load an integer from the given account at the given `slot`.
    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256>;

    /// Delete the given slot from the given account's storage.
    ///
    /// In case of a delete, it may be that certain parts of the subtrie
    /// must be retained. If so, it will be returned as [`Some`].
    fn reporting_destroy_slot(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<MptKey>>;
    fn mask_storage(&mut self, masks: BTreeMap<Address, BTreeSet<MptKey>>) -> anyhow::Result<()>;

    ////////////////////
    /// Other operations
    ////////////////////

    /// _Hash out_ parts of the (state) trie that aren't in `paths`.
    fn mask(&mut self, paths: impl IntoIterator<Item = Self::SubtriePath>) -> anyhow::Result<()>;

    /// Return an identifier for the world.
    fn root(&mut self) -> H256;
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Type1World {
    state: StateMpt,
    /// Writes to storage should be reconciled with
    /// [`storage_root`](evm_arithmetization::generation::mpt::AccountRlp)s.
    storage: BTreeMap<H256, StorageTrie>,
}

impl Type1World {
    pub fn new(state: StateMpt, mut storage: BTreeMap<H256, StorageTrie>) -> anyhow::Result<Self> {
        // Initialise the storage tries.
        for (haddr, acct) in state.iter() {
            let storage = storage.entry(haddr).or_insert_with(|| {
                let mut it = StorageTrie::default();
                it.insert_hash(MptKey::default(), acct.storage_root)
                    .expect("empty trie insert cannot fail");
                it
            });
            ensure!(
                storage.root() == acct.storage_root,
                "inconsistent initial storage for hashed address {haddr}"
            )
        }
        Ok(Self { state, storage })
    }
    pub fn state_trie(&self) -> &mpt_trie::partial_trie::HashedPartialTrie {
        self.state.as_hashed_partial_trie()
    }
    pub fn state_trie_mut(&mut self) -> &mut mpt_trie::partial_trie::HashedPartialTrie {
        self.state.as_mut_hashed_partial_trie()
    }
    pub fn into_state_and_storage(self) -> (StateMpt, BTreeMap<H256, StorageTrie>) {
        let Self { state, storage } = self;
        (state, storage)
    }
    pub fn set_storage(&mut self, storage: BTreeMap<H256, StorageTrie>) {
        self.storage = storage;
    }
    fn get_storage_mut(&mut self, address: Address) -> anyhow::Result<&mut StorageTrie> {
        self.storage
            .get_mut(&keccak_hash::keccak(address))
            .context("no such storage")
    }
    pub(crate) fn get_storage(&self) -> Vec<(H256, &HashedPartialTrie)> {
        // TODO(Robin)
        self.storage
            .iter()
            .map(|(key, value)| (*key, value.as_hashed_partial_trie()))
            .collect::<Vec<_>>()
    }
    fn on_storage<T>(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut StorageTrie) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut acct = self
            .state
            .get(keccak_hash::keccak(address))
            .context("no such account")?;
        let storage = self.get_storage_mut(address)?;
        let ret = f(storage)?;
        acct.storage_root = storage.root();
        self.state.insert(keccak_hash::keccak(address), acct)?;
        Ok(ret)
    }
}

impl World for Type1World {
    type SubtriePath = MptKey;
    type CodeHasher = KeccakHash;

    fn contains(&mut self, address: Address) -> anyhow::Result<bool> {
        Ok(self.state.get(keccak_hash::keccak(address)).is_some())
    }
    fn update_balance(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut U256),
    ) -> anyhow::Result<()> {
        let key = keccak_hash::keccak(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        f(&mut acct.balance);
        self.state.insert(key, acct)
    }
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()> {
        let key = keccak_hash::keccak(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        f(&mut acct.nonce);
        self.state.insert(key, acct)
    }
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()> {
        let key = keccak_hash::keccak(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        acct.code_hash = code.right_or_else(Self::CodeHasher::hash);
        self.state.insert(key, acct)
    }
    fn set_code_and_hash(
        &mut self,
        address: Address,
        code: Either<H256, U256>,
        _code_length: Option<U256>,
    ) {
        let key = keccak_hash::keccak(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        acct.code_hash = code.expect_left("MPTs store hashes as H256.");
    }
    fn reporting_destroy(&mut self, address: Address) -> anyhow::Result<Option<Self::SubtriePath>> {
        self.state.reporting_remove(address)
    }
    fn mask(
        &mut self,
        addresses: impl IntoIterator<Item = Self::SubtriePath>,
    ) -> anyhow::Result<()> {
        self.state.mask(addresses)
    }
    fn root(&mut self) -> H256 {
        self.state.root()
    }
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let _clobbered = self
            .storage
            .insert(keccak_hash::keccak(address), StorageTrie::default());
        // ensure!(_clobbered.is_none()); // TODO(0xaatif): fails our tests
        Ok(())
    }
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let removed = self.storage.remove(&keccak_hash::keccak(address));
        ensure!(removed.is_some());
        Ok(())
    }

    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()> {
        self.on_storage(address, |it| {
            it.insert(
                MptKey::from_slot_position(slot),
                alloy::rlp::encode(value.compat()),
            )
        })
    }

    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()> {
        self.on_storage(address, |it| {
            it.insert(MptKey::from_hash(hash), alloy::rlp::encode(value.compat()))
        })
    }

    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256> {
        let bytes = self
            .get_storage_mut(address)?
            .get(&MptKey::from_slot_position(slot))
            .context(format!("no storage at slot {slot} for address {address:x}"))?;
        Ok(rlp::decode(bytes)?)
    }

    fn reporting_destroy_slot(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<MptKey>> {
        self.on_storage(address, |it| {
            it.reporting_remove(MptKey::from_slot_position(slot))
        })
    }

    fn mask_storage(&mut self, masks: BTreeMap<Address, BTreeSet<MptKey>>) -> anyhow::Result<()> {
        let keep = masks
            .keys()
            .map(keccak_hash::keccak)
            .collect::<BTreeSet<_>>();
        self.storage.retain(|haddr, _| keep.contains(haddr));
        for (addr, mask) in masks {
            if let Some(it) = self.storage.get_mut(&keccak_hash::keccak(addr)) {
                it.mask(mask)?
            }
        }
        Ok(())
    }
}

impl World for Type2World {
    type SubtriePath = SmtKey;
    type CodeHasher = PoseidonHash;

    fn contains(&mut self, address: Address) -> anyhow::Result<bool> {
        Ok(self.accounts.contains_key(&address))
    }
    fn update_balance(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut U256),
    ) -> anyhow::Result<()> {
        let acct = self.accounts.entry(address).or_default();
        f(acct.balance.get_or_insert(Default::default()));
        Ok(())
    }
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()> {
        let acct = self.accounts.entry(address).or_default();
        f(acct.nonce.get_or_insert(Default::default()));
        Ok(())
    }
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()> {
        let acct = self.accounts.entry(address).or_default();
        match code {
            Either::Left(bytes) => {
                acct.code_length = Some(U256::from(bytes.len()));
                if bytes.is_empty() {
                    acct.code_hash = None;
                } else {
                    acct.code_hash = Some(Self::CodeHasher::hash(bytes).into_uint());
                }
            }
            Either::Right(hash) => acct.code_hash = Some(hash.into_uint()),
        };
        Ok(())
    }
    fn set_code_and_hash(
        &mut self,
        address: Address,
        code: Either<H256, U256>,
        code_length: Option<U256>,
    ) {
        let acct = self.accounts.entry(address).or_default();
        acct.code_hash = Some(code.expect_right("SMTs store hashes as U256."));
        acct.code_length = code_length;
    }
    fn reporting_destroy(&mut self, address: Address) -> anyhow::Result<Option<Self::SubtriePath>> {
        self.accounts.remove(&address);
        Ok(None)
    }
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()> {
        let _ = address;
        Ok(())
    }
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()> {
        self.accounts
            .entry(address)
            .and_modify(|it| it.storage.clear());
        Ok(())
    }
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()> {
        self.accounts
            .entry(address)
            .or_default()
            .storage
            .insert(slot, value);
        Ok(())
    }
    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()> {
        self.accounts
            .entry(address)
            .or_default()
            .storage
            .insert(hash.into_uint(), value.into_uint());
        Ok(())
    }
    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256> {
        Ok(self
            .accounts
            .get(&address)
            .context("no account")?
            .storage
            .get(&slot)
            .copied()
            .unwrap_or_default())
    }
    fn reporting_destroy_slot(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<MptKey>> {
        self.accounts.entry(address).and_modify(|it| {
            it.storage.remove(&slot);
        });
        Ok(None)
    }
    fn mask_storage(&mut self, masks: BTreeMap<Address, BTreeSet<MptKey>>) -> anyhow::Result<()> {
        let _ = masks;
        Ok(())
    }
    fn mask(&mut self, paths: impl IntoIterator<Item = Self::SubtriePath>) -> anyhow::Result<()> {
        let _ = paths;
        Ok(())
    }
    fn root(&mut self) -> H256 {
        let mut it = [0; 32];
        smt_trie::utils::hashout2u(self.as_smt().root).to_big_endian(&mut it);
        H256(it)
    }
}

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) type StateKey = MptKey;

#[cfg(feature = "cdk_erigon")]
pub(crate) type StateKey = SmtKey;

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) type CodeHasher = KeccakHash;

#[cfg(feature = "cdk_erigon")]
pub(crate) type CodeHasher = PoseidonHash;

impl World for StateWorld {
    type SubtriePath = StateKey;
    type CodeHasher = CodeHasher;

    fn contains(&mut self, address: Address) -> anyhow::Result<bool> {
        match &mut self.state {
            Either::Left(type1) => type1.contains(address),
            Either::Right(type2) => type2.contains(address),
        }
    }
    fn update_balance(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut U256),
    ) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.update_balance(address, f),
            Either::Right(type2) => type2.update_balance(address, f),
        }
    }
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.update_nonce(address, f),
            Either::Right(type2) => type2.update_nonce(address, f),
        }
    }
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.set_code(address, code),
            Either::Right(type2) => type2.set_code(address, code),
        }
    }
    fn set_code_and_hash(
        &mut self,
        address: Address,
        code_hash: Either<H256, U256>,
        code_length: Option<U256>,
    ) {
        match &mut self.state {
            Either::Left(type1) => type1.set_code_and_hash(address, code_hash, code_length),
            Either::Right(type2) => type2.set_code_and_hash(address, code_hash, code_length),
        }
    }
    fn reporting_destroy(&mut self, address: Address) -> anyhow::Result<Option<Self::SubtriePath>> {
        // TODO: Find a way to revamp this
        #[cfg(not(feature = "cdk_erigon"))]
        match &mut self.state {
            Either::Left(type1) => type1.reporting_destroy(address),
            Either::Right(_type2) => unreachable!("Type2 is not supported."),
        }
        #[cfg(feature = "cdk_erigon")]
        match &mut self.state {
            Either::Left(_type1) => unreachable!("Type1 is not supported"),
            Either::Right(type2) => type2.reporting_destroy(address),
        }
    }
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.create_storage(address),
            Either::Right(type2) => type2.create_storage(address),
        }
    }
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.destroy_storage(address),
            Either::Right(type2) => type2.destroy_storage(address),
        }
    }
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.store_int(address, slot, value),
            Either::Right(type2) => type2.store_int(address, slot, value),
        }
    }
    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.store_hash(address, hash, value),
            Either::Right(type2) => type2.store_hash(address, hash, value),
        }
    }
    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256> {
        match &mut self.state {
            Either::Left(type1) => type1.load_int(address, slot),
            Either::Right(type2) => type2.load_int(address, slot),
        }
    }
    fn reporting_destroy_slot(
        &mut self,
        address: Address,
        slot: U256,
    ) -> anyhow::Result<Option<MptKey>> {
        match &mut self.state {
            Either::Left(type1) => type1.reporting_destroy_slot(address, slot),
            Either::Right(type2) => type2.reporting_destroy_slot(address, slot),
        }
    }
    fn mask_storage(&mut self, masks: BTreeMap<Address, BTreeSet<MptKey>>) -> anyhow::Result<()> {
        match &mut self.state {
            Either::Left(type1) => type1.mask_storage(masks),
            Either::Right(type2) => type2.mask_storage(masks),
        }
    }
    fn mask(&mut self, paths: impl IntoIterator<Item = Self::SubtriePath>) -> anyhow::Result<()> {
        #[cfg(not(feature = "cdk_erigon"))]
        match &mut self.state {
            Either::Left(type1) => type1.mask(paths),
            Either::Right(_type2) => unreachable!("Type2 is not supported."),
        }
        #[cfg(feature = "cdk_erigon")]
        match &mut self.state {
            Either::Left(_type1) => unreachable!("Type1 is not supported"),
            Either::Right(type2) => type2.mask(paths),
        }
    }
    fn root(&mut self) -> H256 {
        match &mut self.state {
            Either::Left(type1) => type1.root(),
            Either::Right(type2) => type2.root(),
        }
    }
}

// Having optional fields here is an odd decision,
// but without the distinction,
// the wire tests fail.
// This may be a bug in the SMT library.
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Type2Entry {
    pub balance: Option<U256>,
    pub nonce: Option<U256>,
    pub code_hash: Option<U256>,
    pub code_length: Option<U256>,
    pub storage: BTreeMap<U256, U256>,
}

// This is a buffered version
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Type2World {
    accounts: BTreeMap<Address, Type2Entry>,
    hashed_out: BTreeMap<SmtKey, H256>,
}

impl Type2World {
    /// # Panics
    /// - On untrusted inputs: <https://github.com/0xPolygonZero/zk_evm/issues/348>.
    pub fn as_smt(&self) -> smt_trie::smt::Smt<smt_trie::db::MemoryDb> {
        let mut smt = smt_trie::smt::Smt::<smt_trie::db::MemoryDb>::default();

        for (key, hash) in &self.hashed_out {
            smt.set_hash(
                key.into_smt_bits(),
                smt_trie::smt::HashOut {
                    elements: {
                        let ethereum_types::U256(arr) = hash.into_uint();
                        arr.map(plonky2::field::goldilocks_field::GoldilocksField)
                    },
                },
            );
        }
        for (
            addr,
            Type2Entry {
                balance,
                nonce,
                code_hash,
                code_length,
                storage,
            },
        ) in self.accounts.iter()
        {
            use smt_trie::keys::{key_balance, key_code, key_code_length, key_nonce, key_storage};

            for (value, key_fn) in [
                (balance, key_balance as fn(_) -> _),
                (nonce, key_nonce),
                (code_hash, key_code),
                (code_length, key_code_length),
            ] {
                if let Some(value) = value {
                    smt.set(key_fn(*addr), *value);
                }
            }
            for (slot, value) in storage {
                smt.set(key_storage(*addr, *slot), *value);
            }
        }
        smt
    }

    pub fn new_unchecked(
        accounts: BTreeMap<Address, Type2Entry>,
        hashed_out: BTreeMap<SmtKey, H256>,
    ) -> Self {
        Self {
            accounts,
            hashed_out,
        }
    }
}
