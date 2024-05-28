use std::{
    collections::{HashMap, HashSet},
    iter::once,
    marker::PhantomData,
};

use ethereum_types::{Address, U256};
use mpt_trie::nibbles::Nibbles;

use crate::{
    aliased_crate_types::{AccountRlp, LegacyReceiptRlp},
    decoding::{ProcessedBlockTraceDecode, TraceDecodingResult, TxnMetaState},
    trace_protocol::{BlockTrace, BlockTraceTriePreImages, ContractCodeUsage, TxnInfo},
    types::{
        CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
        TrieRootHash, EMPTY_CODE_HASH, EMPTY_TRIE_HASH,
    },
    utils::hash,
};

pub(crate) type StorageAccess = Vec<HashedStorageAddrNibbles>;
pub(crate) type StorageWrite = Vec<(HashedStorageAddrNibbles, Vec<u8>)>;

pub(crate) trait BlockTraceProcessing {
    type ProcessedPreImage;
    type Output;

    fn process_block_trace(
        image: BlockTraceTriePreImages,
    ) -> TraceDecodingResult<Self::ProcessedPreImage>;

    fn get_account_keys(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<Item = (HashedAccountAddr, AccountRlp)>;

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>>;

    fn create_spec_output(image: Self::ProcessedPreImage) -> Self::Output;
}
#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace<T, D>
where
    D: ProcessedBlockTraceDecode,
{
    pub(crate) spec: T,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
    pub(crate) withdrawals: Vec<(Address, U256)>,
    decode_spec: PhantomData<D>,
}

impl BlockTrace {
    pub(crate) fn into_processed_block_trace<F, P, D>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceDecodingResult<ProcessedBlockTrace<P::Output, D>>
    where
        F: CodeHashResolveFunc,
        P: BlockTraceProcessing,
        D: ProcessedBlockTraceDecode,
    {
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let pre_image_data = P::process_block_trace(self.trie_pre_images)?;

        let all_accounts_in_pre_image: Vec<_> = P::get_account_keys(&pre_image_data).collect();

        let mut code_hash_resolver = CodeHashResolving {
            client_code_hash_resolve_f: &p_meta.resolve_code_hash_fn,
            extra_code_hash_mappings: P::get_any_extra_code_hash_mappings(&pre_image_data)
                .cloned()
                .unwrap_or_default(),
        };

        let last_tx_idx = self.txn_info.len().saturating_sub(1);

        let txn_info = self
            .txn_info
            .into_iter()
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

                t.into_processed_txn_info(
                    &all_accounts_in_pre_image,
                    &extra_state_accesses,
                    &mut code_hash_resolver,
                )
            })
            .collect::<Vec<_>>();

        let spec = P::create_spec_output(pre_image_data);

        Ok(ProcessedBlockTrace {
            spec,
            txn_info,
            withdrawals,
            decode_spec: PhantomData::<D>,
        })
    }
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
    pub(crate) meta: TxnMetaState,
}

#[derive(Debug)]
pub(crate) struct ProcessedContinuationInfo {}

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

    fn insert_code(&mut self, c_hash: CodeHash, code: Vec<u8>) {
        self.extra_code_hash_mappings.insert(c_hash, code);
    }
}

impl TxnInfo {
    fn into_processed_txn_info<F: CodeHashResolveFunc>(
        self,
        all_accounts_in_pre_image: &[(HashedAccountAddr, AccountRlp)],
        extra_state_accesses: &[HashedAccountAddr],
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
                hashed_addr,
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
                .push((hashed_addr, storage_writes_vec));

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

        for &hashed_addr in extra_state_accesses {
            nodes_used_by_txn.state_accesses.push(hashed_addr);
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

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub(crate) state_accesses: Vec<HashedNodeAddr>,
    pub(crate) state_writes: Vec<(HashedAccountAddr, StateTrieWrites)>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub(crate) storage_accesses: Vec<(HashedAccountAddr, StorageAccess)>,
    pub(crate) storage_writes: Vec<(HashedAccountAddr, StorageWrite)>,
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
