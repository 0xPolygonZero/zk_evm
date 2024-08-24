use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{bail, Context as _};
use ethereum_types::{Address, H256, U256};
use evm_arithmetization::generation::mpt::LegacyReceiptRlp;
use itertools::Itertools as _;
use zk_evm_common::EMPTY_TRIE_HASH;

use crate::typed_mpt::{StateMpt, StateTrie as _, TrieKey};
use crate::{hash, TxnTrace};
use crate::{ContractCodeUsage, TxnInfo};

const FIRST_PRECOMPILE_ADDRESS: U256 = U256([1, 0, 0, 0]);
const LAST_PRECOMPILE_ADDRESS: U256 = U256([10, 0, 0, 0]);

#[derive(Debug, Default)]
pub(crate) struct BatchInfo {
    pub touch: BatchTouch,
    pub contract_code_accessed: HashSet<Vec<u8>>,
    pub meta: Vec<TxnMetaState>,
}

/// Code hash mappings that we have constructed from parsing the block
/// trace.
/// If there are any txns that create contracts, then they will also
/// get added here as we process the deltas.
pub(crate) struct Hash2Code {
    /// Key must always be [`hash`] of value.
    inner: HashMap<H256, Vec<u8>>,
}

impl Hash2Code {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }
    fn get(&mut self, hash: H256) -> anyhow::Result<Vec<u8>> {
        match self.inner.get(&hash) {
            Some(code) => Ok(code.clone()),
            None => bail!("no code for hash {}", hash),
        }
    }
    fn insert(&mut self, code: Vec<u8>) {
        self.inner.insert(hash(&code), code);
    }
}

impl FromIterator<Vec<u8>> for Hash2Code {
    fn from_iter<II: IntoIterator<Item = Vec<u8>>>(iter: II) -> Self {
        let mut this = Self::new();
        this.extend(iter);
        this
    }
}

impl Extend<Vec<u8>> for Hash2Code {
    fn extend<II: IntoIterator<Item = Vec<u8>>>(&mut self, iter: II) {
        for it in iter {
            self.insert(it)
        }
    }
}

impl TxnInfo {
    pub(crate) fn batch(
        batch: &[Self],
        state: &StateMpt,
        extra_state_accesses: &[Address],
        hash2code: &mut Hash2Code,
    ) -> anyhow::Result<BatchInfo> {
        let mut touch = BatchTouch::default();
        let mut contract_code_accessed = HashSet::from([vec![]]); // we always "access" empty code
        let mut meta = Vec::with_capacity(batch.len());

        for txn in batch {
            let mut created_accounts = BTreeSet::new();

            for (
                addr,
                TxnTrace {
                    balance,
                    nonce,
                    storage_read,
                    storage_written,
                    code_usage,
                    self_destructed,
                },
            ) in &txn.traces
            {
                // record storage changes
                let storage_access_keys = storage_read.iter().chain(storage_written.keys());

                if let Some(storage) = touch.storage_accesses.get_mut(&hash(addr)) {
                    storage.extend(
                        storage_access_keys
                            .map(|H256(bytes)| TrieKey::from_hash(hash(bytes)))
                            .collect_vec(),
                    )
                } else {
                    touch.storage_accesses.insert(
                        hash(addr),
                        storage_access_keys
                            .map(|H256(bytes)| TrieKey::from_hash(hash(bytes)))
                            .collect(),
                    );
                };

                // record state changes
                let state_write = StateWrite {
                    balance: *balance,
                    nonce: *nonce,
                    storage_trie_change: !storage_written.is_empty(),
                    code_hash: code_usage.as_ref().map(|it| match it {
                        ContractCodeUsage::Read(hash) => *hash,
                        ContractCodeUsage::Write(bytes) => hash(bytes),
                    }),
                };

                if state_write != StateWrite::default() {
                    // a write occurred

                    // Account creations are flagged to handle reverts.
                    if !state.contains_address(*addr) {
                        created_accounts.insert(*addr);
                    }

                    // Some edge case may see a contract creation followed by a `SELFDESTRUCT`, with
                    // then a follow-up transaction within the same batch updating the state of the
                    // account. If that happens, we should not delete the account after processing
                    // this batch.
                    touch.self_destructed_accounts.remove(addr);

                    if let Some(existing_state_write) = touch.state_writes.get_mut(addr) {
                        // The entry already exists, so we update only the relevant fields.
                        if state_write.balance.is_some() {
                            existing_state_write.balance = state_write.balance;
                        }
                        if state_write.nonce.is_some() {
                            existing_state_write.nonce = state_write.nonce;
                        }
                        if state_write.storage_trie_change {
                            existing_state_write.storage_trie_change =
                                state_write.storage_trie_change;
                        }
                        if state_write.code_hash.is_some() {
                            existing_state_write.code_hash = state_write.code_hash;
                        }
                    } else {
                        touch.state_writes.insert(*addr, state_write);
                    }
                }

                for (k, v) in storage_written {
                    if let Some(storage) = touch.storage_writes.get_mut(&hash(addr)) {
                        storage.insert(TrieKey::from_hash(*k), rlp::encode(v).to_vec());
                    } else {
                        touch.storage_writes.insert(
                            hash(addr),
                            HashMap::from_iter([(TrieKey::from_hash(*k), rlp::encode(v).to_vec())]),
                        );
                    }
                }

                let is_precompile = (FIRST_PRECOMPILE_ADDRESS..LAST_PRECOMPILE_ADDRESS)
                    .contains(&U256::from_big_endian(&addr.0));

                // Trie witnesses will only include accessed precompile accounts as hash
                // nodes if the transaction calling them reverted. If this is the case, we
                // shouldn't include them in this transaction's `state_accesses` to allow the
                // decoder to build a minimal state trie without hitting any hash node.
                if !is_precompile || state.get_by_address(*addr).is_some() {
                    touch.state_accesses.insert(*addr);
                }

                match code_usage {
                    Some(ContractCodeUsage::Read(hash)) => {
                        contract_code_accessed.insert(hash2code.get(*hash)?);
                    }
                    Some(ContractCodeUsage::Write(code)) => {
                        contract_code_accessed.insert(code.clone());
                        hash2code.insert(code.to_vec());
                    }
                    None => {}
                }

                if *self_destructed {
                    touch.self_destructed_accounts.insert(*addr);
                }
            }

            for &addr in extra_state_accesses {
                touch.state_accesses.insert(addr);
            }

            let accounts_with_storage_accesses = touch
                .storage_accesses
                .iter()
                .filter(|(_, slots)| !slots.is_empty())
                .map(|(addr, _)| *addr)
                .collect::<HashSet<_>>();

            let accounts_with_storage_but_no_storage_accesses = state
                .iter()
                .filter(|(_, data)| data.storage_root != EMPTY_TRIE_HASH)
                .filter(|&(addr, _data)| !accounts_with_storage_accesses.contains(&hash(addr)))
                .map(|(addr, data)| (addr, data.storage_root));

            touch
                .accts_with_unaccessed_storage
                .extend(accounts_with_storage_but_no_storage_accesses);

            meta.push(TxnMetaState {
                txn_bytes: match txn.meta.byte_code.is_empty() {
                    false => Some(txn.meta.byte_code.clone()),
                    true => None,
                },
                receipt_node_bytes: check_receipt_bytes(
                    txn.meta.new_receipt_trie_node_byte.clone(),
                )?,
                gas_used: txn.meta.gas_used,
                created_accounts,
            });
        }

        Ok(BatchInfo {
            touch,
            contract_code_accessed,
            meta,
        })
    }
}

fn check_receipt_bytes(bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    match rlp::decode::<LegacyReceiptRlp>(&bytes) {
        Ok(_) => Ok(bytes),
        Err(_) => {
            rlp::decode(&bytes).context("couldn't decode receipt as a legacy receipt or raw bytes")
        }
    }
}

/// Trie nodes that are touched in a particular batch.
///
/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct BatchTouch {
    pub state_accesses: HashSet<Address>,
    pub state_writes: HashMap<Address, StateWrite>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub storage_accesses: HashMap<H256, Vec<TrieKey>>,
    pub storage_writes: HashMap<H256, HashMap<TrieKey, Vec<u8>>>,

    /// Hashed address -> storage root.
    pub accts_with_unaccessed_storage: HashMap<H256, H256>,
    pub self_destructed_accounts: HashSet<Address>,
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct StateWrite {
    pub balance: Option<U256>,
    pub nonce: Option<U256>,
    pub storage_trie_change: bool,
    pub code_hash: Option<H256>,
}

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    /// [`None`] if this is a dummy transaction inserted for padding.
    pub txn_bytes: Option<Vec<u8>>,
    pub receipt_node_bytes: Vec<u8>,
    pub gas_used: u64,
    pub created_accounts: BTreeSet<Address>,
}
