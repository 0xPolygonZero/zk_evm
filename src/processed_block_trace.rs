use std::collections::HashMap;
use std::fmt::Debug;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::U256;

use crate::compact::compact_prestate_processing::{process_compact_prestate, PartialTriePreImages};
use crate::decoding::TraceParsingResult;
use crate::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TrieCompact,
    TrieUncompressed, TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr,
    HashedStorageAddrNibbles, OtherBlockData, StorageAddr, StorageVal, TxnProofGenIR,
};
use crate::utils::{hash, print_value_and_hash_nodes_of_trie, print_value_and_hash_nodes_of_storage_trie};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace {
    pub(crate) tries: PartialTriePreImages,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
}

const COMPATIBLE_HEADER_VERSION: u8 = 1;

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
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let mut pre_image_data = process_block_trace_trie_pre_images(self.trie_pre_images);

        add_empty_storage_tries_that_appear_in_trace_but_not_pre_image(&mut pre_image_data.tries.storage, &self.txn_info);

        print_value_and_hash_nodes_of_trie(&pre_image_data.tries.state);

        for (h_addr, s_trie) in pre_image_data.tries.storage.iter() {
            print_value_and_hash_nodes_of_storage_trie(h_addr, s_trie);
        }

        let resolve_code_hash_fn = |c_hash: &_| {
            let resolve_code_hash_fn_ref = &p_meta.resolve_code_hash_fn;
            let extra_code_hash_mappings_ref = &pre_image_data.extra_code_hash_mappings;

            match extra_code_hash_mappings_ref {
                Some(m) => m
                    .get(c_hash)
                    .cloned()
                    .unwrap_or_else(|| (resolve_code_hash_fn_ref)(c_hash)),
                None => (resolve_code_hash_fn_ref)(c_hash),
            }
        };

        ProcessedBlockTrace {
            tries: pre_image_data.tries,
            txn_info: self
                .txn_info
                .into_iter()
                .map(|t| t.into_processed_txn_info(&resolve_code_hash_fn))
                .collect(),
        }
    }
}

// It's not clear to me if the client should have an empty storage trie for when a txn performs the accounts first storage access, but we're going to assume they won't for now and deal with that case here.
fn add_empty_storage_tries_that_appear_in_trace_but_not_pre_image(s_tries: &mut HashMap<HashedAccountAddr, HashedPartialTrie>, txn_traces: &[TxnInfo]) {
    let all_addrs_that_access_storage_iter = txn_traces.iter().flat_map(|x| x.traces.keys().map(|addr| hash(addr.as_bytes())));
    let addrs_with_storage_access_without_s_tries_iter: Vec<_> = all_addrs_that_access_storage_iter.filter(|addr| !s_tries.contains_key(addr)).collect();

    s_tries.extend(addrs_with_storage_access_without_s_tries_iter.into_iter().map(|k| (k, HashedPartialTrie::default())));
}

#[derive(Debug)]
struct ProcessedBlockTracePreImages {
    tries: PartialTriePreImages,
    extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

fn process_block_trace_trie_pre_images(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> ProcessedBlockTracePreImages {
    match block_trace_pre_images {
        BlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images(t),
        BlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(tries: CombinedPreImages) -> ProcessedBlockTracePreImages {
    match tries {
        CombinedPreImages::Compact(t) => process_compact_trie(t),
    }
}

fn process_separate_trie_pre_images(tries: SeparateTriePreImages) -> ProcessedBlockTracePreImages {
    let tries = PartialTriePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
    };

    ProcessedBlockTracePreImages {
        tries,
        extra_code_hash_mappings: None,
    }
}

fn process_state_trie(trie: SeparateTriePreImage) -> HashedPartialTrie {
    match trie {
        SeparateTriePreImage::Uncompressed(_) => todo!(),
        SeparateTriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: SeparateStorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        SeparateStorageTriesPreImage::SingleTrie(t) => process_single_combined_storage_tries(t),
        SeparateStorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_combined_storage_tries(
    _trie: TrieUncompressed,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, SeparateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(trie: TrieCompact) -> ProcessedBlockTracePreImages {
    // TODO: Wrap in proper result type...
    let out = process_compact_prestate(trie).unwrap();

    // TODO: Make this into a result...
    assert!(out.header.version_is_compatible(COMPATIBLE_HEADER_VERSION));

    ProcessedBlockTracePreImages {
        tries: out.witness_out.tries,
        extra_code_hash_mappings: out.witness_out.code,
    }
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
        let block_bloom = self.block_bloom();

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
                        contract_code_accessed.insert(c_hash, c_bytes.0);
                    }
                }
            }
        }

        let new_meta_state = TxnMetaState {
            txn_bytes: self.meta.byte_code,
            gas_used: self.meta.gas_used,
            block_bloom,
        };

        ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta: new_meta_state,
        }
    }

    fn block_bloom(&self) -> Bloom {
        let mut bloom = [U256::zero(); 8];

        // Note that bloom can be empty.
        for (i, v) in self
            .meta
            .new_receipt_trie_node_byte
            .bloom
            .clone()
            .into_iter()
            .array_chunks::<32>()
            .enumerate()
        {
            bloom[i] = U256::from_big_endian(v.as_slice());
        }

        bloom
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

// TODO: Remove/rename function based on how complex this gets...
fn storage_addr_to_nibbles_even_nibble_fixed_hashed(addr: &StorageAddr) -> Nibbles {
    // I think this is all we need to do? Yell at me if this breaks things.
    // H256's are never going to be truncated I think.

    let hashed_addr = hash(addr.as_bytes());
    Nibbles::from_h256_be(hashed_addr)
}
