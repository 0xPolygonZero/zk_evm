use std::collections::HashMap;
use std::fmt::Debug;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::U256;

use crate::trace_protocol::{
    BlockTrace, BlockUsedContractCode, ContractCodeUsage, StorageTriesPreImage, TrieCompact,
    TriePreImage, TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles, StorageAddr,
    StorageVal,
};
use crate::utils::hash;

pub(crate) struct ProcessedBlockTrace {
    pub(crate) state_trie: HashedPartialTrie,
    pub(crate) storage_tries: HashMap<HashedAccountAddr, HashedPartialTrie>,
    pub(crate) contract_code: HashMap<CodeHash, Vec<u8>>,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
}

impl BlockTrace {
    fn into_processed_block_trace<F>(self, p_meta: &ProcessingMeta<F>) -> ProcessedBlockTrace
    where
        F: Fn(&CodeHash) -> Vec<u8>,
    {
        ProcessedBlockTrace {
            state_trie: process_state_trie(self.state_trie),
            storage_tries: process_storage_tries(self.storage_tries),
            contract_code: process_block_used_contract_code(
                self.contract_code,
                &p_meta.resolve_code_hash_fn,
            ),
            txn_info: self.txn_info.into_iter().map(|t| t.into()).collect(),
        }
    }
}

fn process_state_trie(trie: TriePreImage) -> HashedPartialTrie {
    match trie {
        TriePreImage::Uncompressed(_) => todo!(),
        TriePreImage::Compact(t) => process_compact_trie(t),
        TriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: StorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        StorageTriesPreImage::SingleTrie(t) => process_single_storage_trie(t),
        StorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_storage_trie(
    _trie: TriePreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, TriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(_trie: TrieCompact) -> HashedPartialTrie {
    todo!()
}

fn process_block_used_contract_code<F>(
    code: BlockUsedContractCode,
    resolve_code_hash_fn: &F,
) -> HashMap<CodeHash, Vec<u8>>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    match code {
        BlockUsedContractCode::Full(c) => c,
        BlockUsedContractCode::Digests(d) => {
            let code_hash_to_code_iter = d
                .into_iter()
                .map(|c_hash| (c_hash, resolve_code_hash_fn(&c_hash)));
            HashMap::from_iter(code_hash_to_code_iter)
        }
    }
}

#[derive(Debug)]
pub struct ProcessingMeta<F>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    resolve_code_hash_fn: F,
}

impl<F> ProcessingMeta<F>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    pub fn new(resolve_code_hash_fn: F) -> Self {
        Self {
            resolve_code_hash_fn,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessedTxnInfo {
    pub(crate) nodes_used_by_txn: NodesUsedByTxn,
    pub(crate) contract_code_read: Vec<CodeHash>,
    pub(crate) contract_code_created: Vec<(CodeHash, Vec<u8>)>,
    pub(crate) new_meta_state: BlockMetaState,
}

impl From<TxnInfo> for ProcessedTxnInfo {
    fn from(v: TxnInfo) -> Self {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_read = Vec::new();
        let mut contract_code_created = Vec::new();

        for (addr, trace) in v.traces {
            let hashed_addr = hash(addr.as_bytes());

            let storage_writes = trace.storage_written.unwrap_or_default();

            let storage_read_keys = trace.storage_read.into_iter().flat_map(|reads| {
                reads
                    .into_iter()
                    .map(|addr| storage_addr_to_nibbles_even_nibble_fixed_hashed(&addr))
            });

            let storage_write_keys = storage_writes
                .keys()
                .map(storage_addr_to_nibbles_even_nibble_fixed_hashed);
            let storage_access_keys = storage_read_keys.chain(storage_write_keys);

            nodes_used_by_txn
                .storage_accesses
                .push((hashed_addr, storage_access_keys.collect()));

            let storage_trie_change = !storage_writes.is_empty();
            let code_change = trace.code_usage.is_some();
            let state_write_occurred = trace.balance.is_some()
                || trace.nonce.is_some()
                || storage_trie_change
                || code_change;

            if state_write_occurred {
                let state_trie_writes = StateTrieWrites {
                    balance: trace.balance,
                    nonce: trace.nonce,
                    storage_trie_change,
                    code_hash: trace.code_usage.as_ref().map(|usage| usage.get_code_hash()),
                };

                nodes_used_by_txn
                    .state_writes
                    .push((hashed_addr, state_trie_writes))
            }

            let storage_writes_vec = storage_writes
                .into_iter()
                .map(|(k, v)| (storage_addr_to_nibbles_even_nibble_fixed_hashed(&k), v))
                .collect();
            nodes_used_by_txn
                .storage_writes
                .push((hashed_addr, storage_writes_vec));

            nodes_used_by_txn.state_accesses.push(hashed_addr);

            if let Some(c_usage) = trace.code_usage {
                match c_usage {
                    ContractCodeUsage::Read(c_hash) => contract_code_read.push(c_hash),
                    ContractCodeUsage::Write(c_bytes) => {
                        let c_hash = hash(&c_bytes);

                        contract_code_read.push(c_hash);
                        contract_code_created.push((c_hash, c_bytes));
                    }
                }
            }
        }

        let new_meta_state = BlockMetaState {
            gas_used: v.meta.gas_used,
            block_bloom: v.meta.bloom,
        };

        Self {
            nodes_used_by_txn,
            contract_code_read,
            contract_code_created,
            new_meta_state,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub(crate) state_accesses: Vec<HashedNodeAddr>,
    pub(crate) state_writes: Vec<(HashedAccountAddr, StateTrieWrites)>,
    pub(crate) storage_accesses: Vec<(HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    pub(crate) storage_writes: Vec<(
        HashedAccountAddr,
        Vec<(HashedStorageAddrNibbles, StorageVal)>,
    )>,
}

#[derive(Debug)]
pub(crate) struct StateTrieWrites {
    pub(crate) balance: Option<U256>,
    pub(crate) nonce: Option<U256>,
    pub(crate) storage_trie_change: bool,
    pub(crate) code_hash: Option<CodeHash>,
}

#[derive(Debug)]
enum TraceStorageAccess {
    Read(StorageAddr),
    Write(StorageAddr, StorageVal),
}

#[derive(Debug, Default)]
pub(crate) struct BlockMetaState {
    pub(crate) gas_used: u64,
    pub(crate) block_bloom: Bloom,
}

fn storage_addr_to_nibbles_even_nibble_fixed_hashed(_addr: &StorageAddr) -> Nibbles {
    todo!()
}
