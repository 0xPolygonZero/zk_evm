use std::collections::HashMap;
use std::fmt::Debug;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::U256;
use plonky2_evm::generation::GenerationInputs;

use crate::decoding::TraceParsingResult;
use crate::trace_protocol::{
    BlockTrace, ContractCodeUsage, StorageTriesPreImage, TrieCompact, TriePreImage, TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr,
    HashedStorageAddrNibbles, OtherBlockData, StorageAddr, StorageVal,
};
use crate::utils::hash;

pub(crate) struct ProcessedBlockTrace {
    pub(crate) state_trie: HashedPartialTrie,
    pub(crate) storage_tries: HashMap<HashedAccountAddr, HashedPartialTrie>,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
}

impl BlockTrace {
    pub fn into_proof_generation_inputs<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceParsingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let proced_block_trace = self.into_processed_block_trace(p_meta);
        proced_block_trace.into_generation_inputs(other_data)
    }

    fn into_processed_block_trace<F>(self, p_meta: &ProcessingMeta<F>) -> ProcessedBlockTrace
    where
        F: CodeHashResolveFunc,
    {
        ProcessedBlockTrace {
            state_trie: process_state_trie(self.state_trie),
            storage_tries: process_storage_tries(self.storage_tries),
            txn_info: self
                .txn_info
                .into_iter()
                .map(|t| t.into_processed_txn_info(&p_meta.resolve_code_hash_fn))
                .collect(),
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

#[derive(Debug)]
pub struct ProcessingMeta<F>
where
    F: CodeHashResolveFunc,
{
    resolve_code_hash_fn: F,
}

impl<F> ProcessingMeta<F>
where
    F: CodeHashResolveFunc,
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
    pub(crate) contract_code_accessed: HashMap<CodeHash, Vec<u8>>,
    pub(crate) meta: TxnMetaState,
}

impl TxnInfo {
    fn into_processed_txn_info<F: CodeHashResolveFunc>(
        self,
        code_hash_resolve_f: &F,
    ) -> ProcessedTxnInfo {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_accessed = HashMap::new();

        for (addr, trace) in self.traces {
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
                    ContractCodeUsage::Read(c_hash) => {
                        contract_code_accessed
                            .entry(c_hash)
                            .or_insert_with(|| code_hash_resolve_f(&c_hash));
                    }
                    ContractCodeUsage::Write(c_bytes) => {
                        let c_hash = hash(&c_bytes);
                        contract_code_accessed.insert(c_hash, c_bytes);
                    }
                }
            }
        }

        let new_meta_state = TxnMetaState {
            txn_bytes: self.meta.byte_code,
            gas_used: self.meta.gas_used,
            block_bloom: self.meta.bloom,
        };

        ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta: new_meta_state,
        }
    }
}

/// Note that "*_accesses" includes writes.
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

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    pub(crate) txn_bytes: Vec<u8>,
    pub(crate) gas_used: u64,
    pub(crate) block_bloom: Bloom,
}

fn storage_addr_to_nibbles_even_nibble_fixed_hashed(_addr: &StorageAddr) -> Nibbles {
    todo!()
}
