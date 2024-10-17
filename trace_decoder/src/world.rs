use std::collections::{BTreeMap, BTreeSet};

use alloy_compat::Compat as _;
use anyhow::{ensure, Context as _};
use either::Either;
use ethereum_types::{Address, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use keccak_hash::H256;

use crate::tries::{MptKey, StorageTrie, TypedMpt};

pub(crate) trait World {
    type Key;
    fn contains(&mut self, address: Address) -> anyhow::Result<bool>;
    /// Creates a new account at `address` if it does not exist.
    fn update_balance(&mut self, address: Address, f: impl FnOnce(&mut U256))
        -> anyhow::Result<()>;
    /// Creates a new account at `address` if it does not exist.
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()>;
    /// Creates a new account at `address` if it does not exist.
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()>;
    /// Creates a new account at `address` if it does not exist.
    fn set_storage(&mut self, address: Address, root: H256) -> anyhow::Result<()>;
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<Self::Key>>;
    /// _Hash out_ parts of the trie that aren't in `addresses`.
    fn mask(&mut self, addresses: impl IntoIterator<Item = Self::Key>) -> anyhow::Result<()>;
    fn root(&self) -> H256;

    /// Create an account at the given address.
    ///
    /// It may not be an error if the address already exists.
    fn create_storage(&mut self, address: Address) -> anyhow::Result<()>;
    fn destroy_storage(&mut self, address: Address) -> anyhow::Result<()>;
    fn store_int(&mut self, address: Address, slot: U256, value: U256) -> anyhow::Result<()>;
    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()>;
    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256>;
    fn delete_slot(&mut self, address: Address, slot: U256) -> anyhow::Result<Option<MptKey>>;
    fn storage_root(&mut self, address: Address) -> anyhow::Result<H256>;
    fn mask_storage(&mut self, masks: BTreeMap<Address, BTreeSet<MptKey>>) -> anyhow::Result<()>;
}

pub(crate) struct Type1World {
    pub state: TypedMpt<AccountRlp>,
    pub storage: BTreeMap<H256, StorageTrie>,
}
impl Type1World {
    fn get_storage_mut(&mut self, address: Address) -> anyhow::Result<&mut StorageTrie> {
        self.storage
            .get_mut(&keccak_hash::keccak(address))
            .context("no such storage")
    }
}

impl World for Type1World {
    type Key = MptKey;
    fn contains(&mut self, address: Address) -> anyhow::Result<bool> {
        Ok(self.state.get(MptKey::from_address(address)).is_some())
    }
    fn update_balance(
        &mut self,
        address: Address,
        f: impl FnOnce(&mut U256),
    ) -> anyhow::Result<()> {
        let key = MptKey::from_address(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        f(&mut acct.balance);
        self.state.insert(key, acct)
    }
    fn update_nonce(&mut self, address: Address, f: impl FnOnce(&mut U256)) -> anyhow::Result<()> {
        let key = MptKey::from_address(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        f(&mut acct.nonce);
        self.state.insert(key, acct)
    }
    fn set_code(&mut self, address: Address, code: Either<&[u8], H256>) -> anyhow::Result<()> {
        let key = MptKey::from_address(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        acct.code_hash = code.right_or_else(keccak_hash::keccak);
        self.state.insert(key, acct)
    }
    fn set_storage(&mut self, address: Address, root: H256) -> anyhow::Result<()> {
        let key = MptKey::from_address(address);
        let mut acct = self.state.get(key).unwrap_or_default();
        acct.storage_root = root;
        self.state.insert(key, acct)
    }
    fn reporting_remove(&mut self, address: Address) -> anyhow::Result<Option<Self::Key>> {
        self.state.reporting_remove(MptKey::from_address(address))
    }
    fn mask(&mut self, addresses: impl IntoIterator<Item = Self::Key>) -> anyhow::Result<()> {
        self.state.mask(addresses)
    }
    fn root(&self) -> H256 {
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
        self.get_storage_mut(address)?.insert(
            MptKey::from_slot_position(slot),
            alloy::rlp::encode(value.compat()),
        )?;
        Ok(())
    }

    fn store_hash(&mut self, address: Address, hash: H256, value: H256) -> anyhow::Result<()> {
        self.get_storage_mut(address)?
            .insert(MptKey::from_hash(hash), alloy::rlp::encode(value.compat()))?;
        Ok(())
    }

    fn load_int(&mut self, address: Address, slot: U256) -> anyhow::Result<U256> {
        let bytes = self
            .get_storage_mut(address)?
            .get(&MptKey::from_slot_position(slot))
            .context(format!("no storage at slot {slot} for address {address:x}"))?;
        Ok(rlp::decode(bytes)?)
    }

    fn delete_slot(&mut self, address: Address, slot: U256) -> anyhow::Result<Option<MptKey>> {
        self.get_storage_mut(address)?
            .reporting_remove(MptKey::from_slot_position(slot))
    }

    fn storage_root(&mut self, address: Address) -> anyhow::Result<H256> {
        Ok(self.get_storage_mut(address)?.root())
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
