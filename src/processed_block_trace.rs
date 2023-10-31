use std::collections::HashMap;
use std::fmt::Debug;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::U256;

use crate::decoding::TraceParsingResult;
use crate::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    SeperateStorageTriesPreImage, SeperateTriePreImage, SeperateTriePreImages, TrieCompact,
    TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr,
    HashedStorageAddrNibbles, OtherBlockData, StorageAddr, StorageVal, TxnProofGenIR,
};
use crate::utils::hash;

pub(crate) struct ProcessedBlockTrace {
    pub(crate) state_trie: HashedPartialTrie,
    pub(crate) storage_tries: HashMap<HashedAccountAddr, HashedPartialTrie>,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
}

impl BlockTrace {
    pub fn into_txn_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceParsingResult<Vec<TxnProofGenIR>>
    where
        F: CodeHashResolveFunc,
    {
        let proced_block_trace = self.into_processed_block_trace(p_meta);
        proced_block_trace.into_txn_proof_gen_ir(other_data)
    }

    fn into_processed_block_trace<F>(self, p_meta: &ProcessingMeta<F>) -> ProcessedBlockTrace
    where
        F: CodeHashResolveFunc,
    {
        let pre_image_data = process_block_trace_trie_pre_images(self.trie_pre_images);

        let code_hash_resolve_f = |c_hash: &_| {
            let provided_contract_code_ref = pre_image_data.extra_code_hash_mappings.as_ref();

            provided_contract_code_ref.and_then(|included_c_hash_lookup| {
                included_c_hash_lookup
                    .get(c_hash)
                    .cloned()
                    .or_else(|| Some((p_meta.resolve_code_hash_fn)(c_hash)))
            }).expect("Code hash resolve function should always be able to resolve a code hash to it's byte code but failed to!")
        };

        ProcessedBlockTrace {
            state_trie: pre_image_data.state,
            storage_tries: pre_image_data.storage,
            txn_info: self
                .txn_info
                .into_iter()
                .map(|t| t.into_processed_txn_info(&code_hash_resolve_f))
                .collect(),
        }
    }
}

struct ProcessedBlockTracePreImages {
    state: HashedPartialTrie,
    storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
    extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

fn process_block_trace_trie_pre_images(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> ProcessedBlockTracePreImages {
    match block_trace_pre_images {
        BlockTraceTriePreImages::Seperate(t) => process_seperate_trie_pre_images(t),
        BlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(tries: CombinedPreImages) -> ProcessedBlockTracePreImages {
    match tries {
        CombinedPreImages::Compact(t) => process_compact_trie(t),
    }
}

fn process_seperate_trie_pre_images(tries: SeperateTriePreImages) -> ProcessedBlockTracePreImages {
    ProcessedBlockTracePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
        extra_code_hash_mappings: None,
    }
}

fn process_state_trie(trie: SeperateTriePreImage) -> HashedPartialTrie {
    match trie {
        SeperateTriePreImage::Uncompressed(_) => todo!(),
        SeperateTriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: SeperateStorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        SeperateStorageTriesPreImage::SingleTrie(t) => process_single_storage_trie(t),
        SeperateStorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_storage_trie(
    _trie: SeperateTriePreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, SeperateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(_trie: TrieCompact) -> ProcessedBlockTracePreImages {
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
