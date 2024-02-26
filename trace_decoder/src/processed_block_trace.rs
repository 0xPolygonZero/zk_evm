use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::iter::once;

use ethereum_types::{Address, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};

use crate::compact::compact_prestate_processing::{
    process_compact_prestate_debug, PartialTriePreImages,
};
use crate::decoding::TraceParsingResult;
use crate::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TrieCompact,
    TrieUncompressed, TxnInfo,
};
use crate::types::{
    CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
    OtherBlockData, TrieRootHash, TxnProofGenIR, EMPTY_CODE_HASH, EMPTY_TRIE_HASH,
};
use crate::utils::{
    h_addr_nibs_to_h256, hash, print_value_and_hash_nodes_of_storage_trie,
    print_value_and_hash_nodes_of_trie,
};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace {
    pub(crate) tries: PartialTriePreImages,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
    pub(crate) withdrawals: Vec<(Address, U256)>,
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
        let processed_block_trace =
            self.into_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone());

        processed_block_trace.into_txn_proof_gen_ir(other_data)
    }

    fn into_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> ProcessedBlockTrace
    where
        F: CodeHashResolveFunc,
    {
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let pre_image_data = process_block_trace_trie_pre_images(self.trie_pre_images);

        print_value_and_hash_nodes_of_trie(&pre_image_data.tries.state);

        for (h_addr, s_trie) in pre_image_data.tries.storage.iter() {
            print_value_and_hash_nodes_of_storage_trie(h_addr, s_trie);
        }

        let all_accounts_in_pre_image: Vec<_> = pre_image_data
            .tries
            .state
            .items()
            .filter_map(|(addr, data)| {
                data.as_val().map(|data| {
                    (
                        h_addr_nibs_to_h256(&addr),
                        rlp::decode::<AccountRlp>(data).unwrap(),
                    )
                })
            })
            .collect();

        let mut code_hash_resolver = CodeHashResolving {
            client_code_hash_resolve_f: &p_meta.resolve_code_hash_fn,
            extra_code_hash_mappings: pre_image_data.extra_code_hash_mappings.unwrap_or_default(),
        };

        let txn_info = self
            .txn_info
            .into_iter()
            .map(|t| t.into_processed_txn_info(&all_accounts_in_pre_image, &mut code_hash_resolver))
            .collect::<Vec<_>>();

        ProcessedBlockTrace {
            tries: pre_image_data.tries,
            txn_info,
            withdrawals,
        }
    }
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
    process_compact_trie(tries.compact)
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
    let out = process_compact_prestate_debug(trie).unwrap();

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

struct CodeHashResolving<F> {
    /// If we have not seen this code hash before, use the resolve function that
    /// the client passes down to us. This will likely be an rpc call/cache
    /// check.
    client_code_hash_resolve_f: F,

    /// Code hash mappings that we have constructed from parsing the block
    /// trace. If there are any txns that create contracts, then they will also
    /// get added here as we process the deltas.
    extra_code_hash_mappings: HashMap<CodeHash, Vec<u8>>,
}

impl<F: CodeHashResolveFunc> CodeHashResolving<F> {
    fn resolve(&mut self, c_hash: &CodeHash) -> Vec<u8> {
        match self.extra_code_hash_mappings.get(c_hash) {
            Some(code) => code.clone(),
            None => (self.client_code_hash_resolve_f)(c_hash),
        }
    }

    fn insert_code(&mut self, c_hash: H256, code: Vec<u8>) {
        self.extra_code_hash_mappings.insert(c_hash, code);
    }
}

impl TxnInfo {
    fn into_processed_txn_info<F: CodeHashResolveFunc>(
        self,
        all_accounts_in_pre_image: &[(HashedAccountAddr, AccountRlp)],
        code_hash_resolver: &mut CodeHashResolving<F>,
    ) -> ProcessedTxnInfo {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_accessed = create_empty_code_access_map();

        for (addr, trace) in self.traces {
            let hashed_addr = hash(addr.as_bytes());

            let storage_writes = trace.storage_written.unwrap_or_default();

            let storage_read_keys = trace
                .storage_read
                .into_iter()
                .flat_map(|reads| reads.into_iter());

            let storage_write_keys = storage_writes.keys();
            let storage_access_keys = storage_read_keys.chain(storage_write_keys.copied());

            nodes_used_by_txn.storage_accesses.push((
                Nibbles::from_h256_be(hashed_addr),
                storage_access_keys
                    .map(|k| Nibbles::from_h256_be(hash(&k.0)))
                    .collect(),
            ));

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
                .map(|(k, v)| (Nibbles::from_h256_be(k), rlp::encode(&v).to_vec()))
                .collect();

            nodes_used_by_txn
                .storage_writes
                .push((Nibbles::from_h256_be(hashed_addr), storage_writes_vec));

            nodes_used_by_txn.state_accesses.push(hashed_addr);

            if let Some(c_usage) = trace.code_usage {
                match c_usage {
                    ContractCodeUsage::Read(c_hash) => {
                        contract_code_accessed
                            .entry(c_hash)
                            .or_insert_with(|| code_hash_resolver.resolve(&c_hash));
                    }
                    ContractCodeUsage::Write(c_bytes) => {
                        let c_hash = hash(&c_bytes);

                        contract_code_accessed.insert(c_hash, c_bytes.0.clone());
                        code_hash_resolver.insert_code(c_hash, c_bytes.0);
                    }
                }
            }

            if trace
                .self_destructed
                .map_or(false, |self_destructed| self_destructed)
            {
                nodes_used_by_txn.self_destructed_accounts.push(hashed_addr);
            }
        }

        let accounts_with_storage_accesses: HashSet<_> = HashSet::from_iter(
            nodes_used_by_txn
                .storage_accesses
                .iter()
                .filter(|(_, slots)| !slots.is_empty())
                .map(|(addr, _)| *addr),
        );

        let all_accounts_with_non_empty_storage = all_accounts_in_pre_image
            .iter()
            .filter(|(_, data)| data.storage_root != EMPTY_TRIE_HASH);

        let accounts_with_storage_but_no_storage_accesses = all_accounts_with_non_empty_storage
            .filter(|&(addr, _data)| {
                !accounts_with_storage_accesses.contains(&Nibbles::from_h256_be(*addr))
            })
            .map(|(addr, data)| (*addr, data.storage_root));

        nodes_used_by_txn
            .state_accounts_with_no_accesses_but_storage_tries
            .extend(accounts_with_storage_but_no_storage_accesses);

        let txn_bytes = match self.meta.byte_code.is_empty() {
            false => Some(self.meta.byte_code),
            true => None,
        };

        let receipt_node_bytes =
            process_rlped_receipt_node_bytes(self.meta.new_receipt_trie_node_byte);

        let new_meta_state = TxnMetaState {
            txn_bytes,
            receipt_node_bytes,
            gas_used: self.meta.gas_used,
        };

        ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta: new_meta_state,
        }
    }
}

fn process_rlped_receipt_node_bytes(raw_bytes: Vec<u8>) -> Vec<u8> {
    match rlp::decode::<LegacyReceiptRlp>(&raw_bytes) {
        Ok(_) => raw_bytes,
        Err(_) => {
            // Must be non-legacy.
            rlp::decode::<Vec<u8>>(&raw_bytes).unwrap()
        }
    }
}

fn create_empty_code_access_map() -> HashMap<CodeHash, Vec<u8>> {
    HashMap::from_iter(once((EMPTY_CODE_HASH, Vec::new())))
}

pub(crate) type StorageAccess = Vec<HashedStorageAddrNibbles>;
pub(crate) type StorageWrite = Vec<(HashedStorageAddrNibbles, Vec<u8>)>;

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub(crate) state_accesses: Vec<HashedNodeAddr>,
    pub(crate) state_writes: Vec<(HashedAccountAddr, StateTrieWrites)>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub(crate) storage_accesses: Vec<(Nibbles, StorageAccess)>,
    pub(crate) storage_writes: Vec<(Nibbles, StorageWrite)>,
    pub(crate) state_accounts_with_no_accesses_but_storage_tries:
        HashMap<HashedAccountAddr, TrieRootHash>,
    pub(crate) self_destructed_accounts: Vec<HashedAccountAddr>,
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
    pub(crate) txn_bytes: Option<Vec<u8>>,
    pub(crate) receipt_node_bytes: Vec<u8>,
    pub(crate) gas_used: u64,
}
