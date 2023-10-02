use std::collections::{HashMap, HashSet};
use std::fmt::Debug;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::HashedPartialTrie;
use ethereum_types::U256;

use crate::trace_protocol::{
    BlockTrace, BlockUsedContractCode, ContractCodeUsage, StorageTriesPreImage, TrieCompact,
    TriePreImage, TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, HashedAccountAddr, HashedNodeAddr, HashedStorageAddr,
    HashedStorageAddrNibbles, StorageAddr, StorageVal,
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
    pub(crate) contract_code: Vec<CodeHash>,
    pub(crate) nodes_used_by_txn: NodesUsedByTxn,
    pub(crate) contract_code_created: Vec<(CodeHash, Vec<u8>)>,
    pub(crate) new_meta_state: BlockMetaState,
}

impl From<TxnInfo> for ProcessedTxnInfo {
    fn from(v: TxnInfo) -> Self {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_created = Vec::new();
        // let mut state_trie_writes = Vec::with_capacity(v.traces.len()); // Good
        // assumption?

        for (addr, trace) in v.traces {
            let hashed_addr = hash(addr.as_bytes());

            let s_writes = trace.storage_written.unwrap_or_default();

            let s_read_keys = trace.storage_read.into_iter().flat_map(|reads| {
                reads
                    .into_iter()
                    .map(|addr| storage_addr_to_nibbles_even_nibble_fixed_hashed(&addr))
            });

            let s_write_keys = s_writes
                .keys()
                .map(|k| storage_addr_to_nibbles_even_nibble_fixed_hashed(k));
            let s_access_keys = s_read_keys.chain(s_write_keys);

            nodes_used_by_txn
                .storage_accesses
                .push((hashed_addr, s_access_keys.collect()));
            // nodes_used_by_txn.storage_writes.push((hashed_addr, s_writes));
        }

        // TODO

        Self {
            contract_code: todo!(),
            nodes_used_by_txn,
            contract_code_created,
            new_meta_state: todo!(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    state_accesses: Vec<HashedNodeAddr>,
    state_writes: Vec<StateTrieWrites>,
    storage_accesses: Vec<(HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    storage_writes: Vec<(
        HashedAccountAddr,
        Vec<(HashedStorageAddrNibbles, StorageVal)>,
    )>,
}

#[derive(Debug)]
struct StateTrieWrites {
    balance: Option<U256>,
    nonce: Option<U256>,
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

fn storage_addr_to_nibbles_even_nibble_fixed_hashed(addr: &StorageAddr) -> Nibbles {
    todo!()
}
