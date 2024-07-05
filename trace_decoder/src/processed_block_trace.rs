use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::iter::once;

use ethereum_types::{Address, H256, U256};
use evm_arithmetization::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization::GenerationInputs;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};

use crate::compact::compact_prestate_processing::{
    process_compact_prestate_debug, CompactParsingError, CompactParsingResult,
    PartialTriePreImages, ProcessedCompactOutput,
};
use crate::decoding::{TraceParsingError, TraceParsingResult};
use crate::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TrieCompact,
    TrieUncompressed, TxnInfo,
};
use crate::types::{
    CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
    OtherBlockData, TrieRootHash, EMPTY_CODE_HASH, EMPTY_TRIE_HASH,
};
use crate::utils::{
    hash, print_value_and_hash_nodes_of_storage_trie, print_value_and_hash_nodes_of_trie,
};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace {
    pub(crate) tries: PartialTriePreImages,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
    pub(crate) withdrawals: Vec<(Address, U256)>,
}

const COMPATIBLE_HEADER_VERSIONS: [u8; 2] = [0, 1];

impl BlockTrace {
    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn into_txn_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
        batch_size: usize,
    ) -> TraceParsingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace = self.into_processed_block_trace(
            p_meta,
            other_data.b_data.withdrawals.clone(),
            batch_size,
        )?;

        processed_block_trace.into_txn_proof_gen_ir(other_data, batch_size)
    }

    fn into_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
        batch_size: usize,
    ) -> TraceParsingResult<ProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let pre_image_data = process_block_trace_trie_pre_images(self.trie_pre_images)?;

        print_value_and_hash_nodes_of_trie(&pre_image_data.tries.state);

        for (h_addr, s_trie) in pre_image_data.tries.storage.iter() {
            print_value_and_hash_nodes_of_storage_trie(h_addr, s_trie);
        }

        let all_accounts_in_pre_image: Vec<_> = pre_image_data
            .tries
            .state
            .items()
            .filter_map(|(addr, data)| {
                data.as_val()
                    .map(|data| (addr.into(), rlp::decode::<AccountRlp>(data).unwrap()))
            })
            .collect();

        let code_db = {
            let mut code_db = self.code_db.unwrap_or_default();
            if let Some(code_mappings) = pre_image_data.extra_code_hash_mappings {
                code_db.extend(code_mappings);
            }
            code_db
        };

        let mut code_hash_resolver = CodeHashResolving {
            client_code_hash_resolve_f: &p_meta.resolve_code_hash_fn,
            extra_code_hash_mappings: code_db,
        };

        let last_tx_idx = self.txn_info.len().saturating_sub(1) / batch_size;

        let txn_info = self
            .txn_info
            .chunks(batch_size)
            .enumerate()
            .map(|(i, t)| {
                let extra_state_accesses = if last_tx_idx == i {
                    // If this is the last transaction, we mark the withdrawal addresses
                    // as accessed in the state trie.
                    withdrawals
                        .iter()
                        .map(|(addr, _)| hash(addr.as_bytes()))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                TxnInfo::into_processed_txn_info(
                    t,
                    &all_accounts_in_pre_image,
                    &extra_state_accesses,
                    &mut code_hash_resolver,
                )
            })
            .collect::<Vec<_>>();

        Ok(ProcessedBlockTrace {
            tries: pre_image_data.tries,
            txn_info,
            withdrawals,
        })
    }
}

#[derive(Debug)]
struct ProcessedBlockTracePreImages {
    tries: PartialTriePreImages,
    extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

impl From<ProcessedCompactOutput> for ProcessedBlockTracePreImages {
    fn from(v: ProcessedCompactOutput) -> Self {
        let tries = PartialTriePreImages {
            state: v.witness_out.state_trie,
            storage: v.witness_out.storage_tries,
        };

        Self {
            tries,
            extra_code_hash_mappings: (!v.witness_out.code.is_empty())
                .then_some(v.witness_out.code),
        }
    }
}

fn process_block_trace_trie_pre_images(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> TraceParsingResult<ProcessedBlockTracePreImages> {
    match block_trace_pre_images {
        BlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images(t),
        BlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(
    tries: CombinedPreImages,
) -> TraceParsingResult<ProcessedBlockTracePreImages> {
    Ok(process_compact_trie(tries.compact).map_err(TraceParsingError::from)?)
}

fn process_separate_trie_pre_images(
    tries: SeparateTriePreImages,
) -> TraceParsingResult<ProcessedBlockTracePreImages> {
    let tries = PartialTriePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
    };

    Ok(ProcessedBlockTracePreImages {
        tries,
        extra_code_hash_mappings: None,
    })
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
    tries: HashMap<HashedAccountAddr, SeparateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    tries
        .into_iter()
        .map(|(k, v)| match v {
            SeparateTriePreImage::Uncompressed(_) => todo!(),
            SeparateTriePreImage::Direct(t) => (k, t.0),
        })
        .collect()
}

fn process_compact_trie(trie: TrieCompact) -> CompactParsingResult<ProcessedBlockTracePreImages> {
    let out = process_compact_prestate_debug(trie)?;

    if !COMPATIBLE_HEADER_VERSIONS
        .iter()
        .any(|&v| out.header.version_is_compatible(v))
    {
        return Err(CompactParsingError::IncompatibleVersion(
            COMPATIBLE_HEADER_VERSIONS.to_vec(),
            out.header.version,
        ));
    }

    Ok(out.into())
}

/// Structure storing a function turning a `CodeHash` into bytes.
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
    /// Returns a `ProcessingMeta` given the provided code hash resolving
    /// function.
    pub const fn new(resolve_code_hash_fn: F) -> Self {
        Self {
            resolve_code_hash_fn,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessedTxnInfo {
    pub(crate) nodes_used_by_txn: NodesUsedByTxn,
    pub(crate) contract_code_accessed: HashMap<CodeHash, Vec<u8>>,
    pub(crate) meta: Vec<TxnMetaState>,
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
        tx_infos: &[Self],
        all_accounts_in_pre_image: &[(HashedAccountAddr, AccountRlp)],
        extra_state_accesses: &[HashedAccountAddr],
        code_hash_resolver: &mut CodeHashResolving<F>,
    ) -> ProcessedTxnInfo {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_accessed = create_empty_code_access_map();
        let mut meta = Vec::with_capacity(tx_infos.len());

        for txn in tx_infos.iter() {
            for (addr, trace) in txn.traces.iter() {
                let hashed_addr = hash(addr.as_bytes());

                let storage_writes = trace.storage_written.clone().unwrap_or_default();

                let storage_read_keys = trace
                    .storage_read
                    .clone()
                    .into_iter()
                    .flat_map(|reads| reads.into_iter());

                let storage_write_keys = storage_writes.keys();
                let storage_access_keys = storage_read_keys.chain(storage_write_keys.copied());

                if let Some(storage) = nodes_used_by_txn.storage_accesses.get_mut(&hashed_addr) {
                    storage.extend(
                        &storage_access_keys
                            .map(|k| Nibbles::from_h256_be(hash(&k.0)))
                            .collect::<Vec<Nibbles>>(),
                    )
                } else {
                    nodes_used_by_txn.storage_accesses.insert(
                        hashed_addr,
                        storage_access_keys
                            .map(|k| Nibbles::from_h256_be(hash(&k.0)))
                            .collect::<Vec<Nibbles>>(),
                    );
                };

                let storage_trie_change = !storage_writes.is_empty();
                let code_change = trace.code_usage.is_some();
                let state_write_occurred = trace.balance.is_some()
                    || trace.nonce.is_some()
                    || storage_trie_change
                    || code_change;

                if state_write_occurred {
                    if let Some(state_trie_writes) =
                        nodes_used_by_txn.state_writes.get_mut(&hashed_addr)
                    {
                        // The entry already exists, so we update only the relevant fields.
                        if trace.balance.is_some() {
                            state_trie_writes.balance = trace.balance;
                        }
                        if trace.nonce.is_some() {
                            state_trie_writes.nonce = trace.nonce;
                        }
                        if storage_trie_change {
                            state_trie_writes.storage_trie_change = storage_trie_change;
                        }
                        if code_change {
                            state_trie_writes.code_hash =
                                trace.code_usage.as_ref().map(|usage| usage.get_code_hash());
                        }
                    } else {
                        let state_trie_writes = StateTrieWrites {
                            balance: trace.balance,
                            nonce: trace.nonce,
                            storage_trie_change,
                            code_hash: trace.code_usage.as_ref().map(|usage| usage.get_code_hash()),
                        };

                        nodes_used_by_txn
                            .state_writes
                            .insert(hashed_addr, state_trie_writes);
                    }
                }

                for (k, v) in storage_writes.into_iter() {
                    if let Some(storage) = nodes_used_by_txn.storage_writes.get_mut(&hashed_addr) {
                        storage.insert(Nibbles::from_h256_be(k), rlp::encode(&v).to_vec());
                    } else {
                        nodes_used_by_txn.storage_writes.insert(
                            hashed_addr,
                            HashMap::from_iter([(
                                Nibbles::from_h256_be(k),
                                rlp::encode(&v).to_vec(),
                            )]),
                        );
                    }
                }

                nodes_used_by_txn.state_accesses.insert(hashed_addr);

                if let Some(c_usage) = &trace.code_usage {
                    match c_usage {
                        ContractCodeUsage::Read(c_hash) => {
                            contract_code_accessed
                                .entry(*c_hash)
                                .or_insert_with(|| code_hash_resolver.resolve(c_hash));
                        }
                        ContractCodeUsage::Write(c_bytes) => {
                            let c_hash = hash(c_bytes);

                            contract_code_accessed.insert(c_hash, c_bytes.0.clone());
                            code_hash_resolver.insert_code(c_hash, c_bytes.0.clone());
                        }
                    }
                }

                if trace
                    .self_destructed
                    .map_or(false, |self_destructed| self_destructed)
                {
                    nodes_used_by_txn
                        .self_destructed_accounts
                        .insert(hashed_addr);
                }
            }

            for &hashed_addr in extra_state_accesses {
                nodes_used_by_txn.state_accesses.insert(hashed_addr);
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
                .filter(|&(addr, _data)| !accounts_with_storage_accesses.contains(addr))
                .map(|(addr, data)| (*addr, data.storage_root));

            nodes_used_by_txn
                .state_accounts_with_no_accesses_but_storage_tries
                .extend(accounts_with_storage_but_no_storage_accesses);

            let txn_bytes = match txn.meta.byte_code.is_empty() {
                false => Some(txn.meta.byte_code.clone()),
                true => None,
            };

            let receipt_node_bytes =
                process_rlped_receipt_node_bytes(txn.meta.new_receipt_trie_node_byte.clone());

            meta.push(TxnMetaState {
                txn_bytes,
                receipt_node_bytes,
                gas_used: txn.meta.gas_used,
            });
        }

        ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta,
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
pub(crate) type StorageWrite = HashMap<HashedStorageAddrNibbles, Vec<u8>>;

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub(crate) state_accesses: HashSet<HashedNodeAddr>,
    pub(crate) state_writes: HashMap<HashedAccountAddr, StateTrieWrites>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub(crate) storage_accesses: HashMap<HashedAccountAddr, StorageAccess>,
    pub(crate) storage_writes: HashMap<HashedAccountAddr, StorageWrite>,
    pub(crate) state_accounts_with_no_accesses_but_storage_tries:
        HashMap<HashedAccountAddr, TrieRootHash>,
    pub(crate) self_destructed_accounts: HashSet<HashedAccountAddr>,
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
