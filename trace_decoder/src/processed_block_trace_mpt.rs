use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::iter::once;

use ethereum_types::{Address, H256, U256};
use evm_arithmetization_mpt::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use evm_arithmetization_mpt::GenerationInputs;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::PartialTrie;

use crate::compact::compact_prestate_processing::{
    MptPartialTriePreImages, ProcessedCompactOutput,
};
use crate::decoding_mpt::{CodeHashResolver, TxnMetaState};
use crate::processed_block_trace::ProcessedBlockTrace;
use crate::protocol_processing::{
    process_mpt_block_trace_trie_pre_images, TraceProtocolDecodingResult,
};
use crate::trace_protocol::{AtomicUnitInfo, BlockTrace, ContractCodeUsage, TxnInfo};
use crate::types::{
    CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
    OtherBlockData, TrieRootHash, EMPTY_CODE_HASH, EMPTY_TRIE_HASH,
};
use crate::utils::{
    hash, print_value_and_hash_nodes_of_storage_trie, print_value_and_hash_nodes_of_trie,
};

pub(crate) type MptProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceMptSpec>;

pub(crate) type StorageAccess = Vec<HashedStorageAddrNibbles>;
pub(crate) type StorageWrite = Vec<(HashedStorageAddrNibbles, Vec<u8>)>;

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceMptSpec {
    pub(crate) tries: MptPartialTriePreImages,
    pub(crate) sect_info: ProcessedSectionInfo,
}

impl BlockTrace {
    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn into_proof_gen_mpt_ir<F>(
        self,
        c_resolve: &CodeHashResolveFunc,
        other_data: OtherBlockData,
    ) -> TraceProtocolDecodingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolver,
    {
        let processed_block_trace =
            self.into_mpt_processed_block_trace(c_resolve, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }

    fn into_mpt_processed_block_trace(
        self,
        c_resolve: &CodeHashResolveFunc,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceProtocolDecodingResult<MptProcessedBlockTrace> {
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let pre_image_data = process_mpt_block_trace_trie_pre_images(self.trie_pre_images)?;

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

        let mut code_hash_resolver = MPTCodeHashResolving {
            client_code_hash_resolve_f: &c_resolve,
            extra_code_hash_mappings: pre_image_data.extra_code_hash_mappings.unwrap_or_default(),
        };

        let sect_info = Self::process_atomic_units(
            self.atomic_info,
            &all_accounts_in_pre_image,
            &mut code_hash_resolver,
            &withdrawals,
        );

        let spec = ProcedBlockTraceMptSpec {
            tries: pre_image_data.tries,
            sect_info,
        };

        Ok(ProcessedBlockTrace { spec, withdrawals })
    }

    fn process_atomic_units<F>(
        atomic_info: AtomicUnitInfo,
        all_accounts_in_pre_image: &[(HashedAccountAddr, AccountRlp)],
        code_hash_resolver: &mut MPTCodeHashResolving<F>,
        withdrawals: &[(Address, U256)],
    ) -> ProcessedSectionInfo
    where
        F: CodeHashResolveFunc,
    {
        match atomic_info {
            AtomicUnitInfo::Txn(txn_info) => {
                let last_tx_idx = txn_info.len().saturating_sub(1);

                let proced_txn_info = txn_info
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
                            all_accounts_in_pre_image,
                            &extra_state_accesses,
                            code_hash_resolver,
                        )
                    })
                    .collect::<Vec<_>>();

                ProcessedSectionInfo::Txns(proced_txn_info)
            }
            AtomicUnitInfo::Continuations(_) => {
                todo!("Continuation support with MPT not yet implemented!")
            }
        }
    }
}

/// Mpt processed pre-image.
#[derive(Clone, Debug)]
pub struct MptProcessedBlockTracePreImages {
    pub(crate) tries: MptPartialTriePreImages,
    pub(crate) extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

impl From<ProcessedCompactOutput> for MptProcessedBlockTracePreImages {
    fn from(v: ProcessedCompactOutput) -> Self {
        let tries = MptPartialTriePreImages {
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

#[derive(Debug)]
pub(crate) enum ProcessedSectionInfo {
    #[allow(dead_code)]
    Continuations(Vec<ProcessedContinuationInfo>),
    Txns(Vec<ProcessedSectionTxnInfo>),
}

#[derive(Debug)]
pub(crate) struct ProcessedSectionTxnInfo {
    pub(crate) nodes_used_by_txn: NodesUsedByTxn,
    pub(crate) contract_code_accessed: HashMap<CodeHash, Vec<u8>>,
    pub(crate) meta: TxnMetaState,
}

#[derive(Debug)]
pub(crate) struct ProcessedContinuationInfo {}

struct MPTCodeHashResolving<F> {
    /// If we have not seen this code hash before, use the resolve function that
    /// the client passes down to us. This will likely be an rpc call/cache
    /// check.
    client_code_hash_resolve_f: F,

    /// Code hash mappings that we have constructed from parsing the block
    /// trace. If there are any txns that create contracts, then they will also
    /// get added here as we process the deltas.
    extra_code_hash_mappings: HashMap<CodeHash, Vec<u8>>,
}

impl<F: CodeHashResolveFunc> CodeHashResolver for MPTCodeHashResolving<F> {
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
        extra_state_accesses: &[HashedAccountAddr],
        code_hash_resolver: &mut MPTCodeHashResolving<F>,
    ) -> ProcessedSectionTxnInfo {
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

        ProcessedSectionTxnInfo {
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
