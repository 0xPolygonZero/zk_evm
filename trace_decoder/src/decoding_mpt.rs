use std::{
    collections::HashMap,
    iter::{self, empty, once},
};

use ethereum_types::{Address, U256, U512};
use evm_arithmetization_mpt::GenerationInputs;
use keccak_hash::H256;
use log::trace;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    special_query::path_for_query,
    trie_ops::{TrieOpError, TrieOpResult},
    trie_subsets::{create_trie_subset, SubsetTrieError},
    utils::{IntoTrieKey, TriePath},
};

use crate::{
    aliased_crate_types::{
        MptAccountRlp, MptExtraBlockData, MptGenerationInputs, MptTrieInputs, MptTrieRoots,
    }, compact::compact_mpt_processing::MptPartialTriePreImages, decoding::{
        ProcessedBlockTraceDecode, TraceDecodingError, TraceDecodingResult, TraceParsingError, TraceParsingErrorReason, TrieType
    }, processed_block_trace::{
        NodesUsedByTxn, ProcessedSectionInfo, ProcessedSectionTxnInfo, ProcessingMeta, StateTrieWrites
    }, processed_block_trace_mpt::{MptBlockTraceProcessing, MptProcessedBlockTrace, ProcedBlockTraceMptSpec}, protocol_processing::TraceProtocolDecodingResult, trace_protocol::BlockTrace, types::{
        CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, HashedStorageAddrNibbles, OtherBlockData, TrieRootHash, TxnIdx, EMPTY_ACCOUNT_BYTES_RLPED, ZERO_STORAGE_SLOT_VAL_RLPED
    }, utils::{hash, update_val_if_some}
};

// TODO: Make a final decision if we need a separate error for MPT...
pub(crate) type MptTraceParsingError = TraceParsingError;

impl ProcessedBlockTraceDecode for MptProcessedBlockTrace {
    type Spec = ProcedBlockTraceMptSpec;
    type CurrBlockTries = PartialTrieState;
    type TrieInputs;
    type AccountRlp;
    type Ir;
    type TState;

    fn get_trie_pre_image(spec: &Self::Spec) -> Self::TState {
        Self::TState {
            state: spec.tries.state.clone(),
            storage: spec.tries.storage.clone(),
            ..Default::default()
        }
    }

    fn delete_node(h_addr: &Nibbles) {
        todo!()
    }

    fn write_account_data(h_addr: HashedAccountAddr, data: evm_arithmetization_mpt::generation::mpt::AccountRlp) {
        todo!()
    }

    fn delete_account(h_addr: HashedAccountAddr) {
        todo!()
    }

    fn set_storage_slot(h_addr: HashedAccountAddr, h_slot: HashedAccountAddr, val: crate::types::StorageVal) {
        todo!()
    }

    fn create_trie_subsets(tries: &Self::CurrBlockTries) -> Self::TrieInputs {
        todo!()
    }
}

impl MptProcessedBlockTrace {
    pub(crate) fn into_proof_gen_mpt_ir(
        self,
        other_data: OtherBlockData,
    ) -> MptTraceParsingResult<Vec<MptGenerationInputs>> {
        todo!()
    }

    /// If a branch collapse occurred after a delete, then we must ensure that
    /// the other single child that remains also is not hashed when passed into
    /// plonky2. Returns the key to the remaining child if a collapse occured.
    fn delete_node_and_report_remaining_key_if_branch_collapsed(
        trie: &mut HashedPartialTrie,
        delete_k: &Nibbles,
    ) -> TrieOpResult<Option<Nibbles>> {
        let old_trace = Self::get_trie_trace(trie, delete_k);
        trie.delete(*delete_k)?;
        let new_trace = Self::get_trie_trace(trie, delete_k);

        Ok(Self::node_deletion_resulted_in_a_branch_collapse(
            &old_trace, &new_trace,
        ))
    }

    fn get_trie_trace(trie: &HashedPartialTrie, k: &Nibbles) -> TriePath {
        path_for_query(trie, *k, true).collect()
    }

    /// Comparing the path of the deleted key before and after the deletion,
    /// determine if the deletion resulted in a branch collapsing into a leaf or
    /// extension node, and return the path to the remaining child if this
    /// occurred.
    fn node_deletion_resulted_in_a_branch_collapse(
        old_path: &TriePath,
        new_path: &TriePath,
    ) -> Option<Nibbles> {
        // Collapse requires at least 2 nodes.
        if old_path.0.len() < 2 {
            return None;
        }

        // If the node path length decreased after the delete, then a collapse occurred.
        // As an aside, note that while it's true that the branch could have collapsed
        // into an extension node with multiple nodes below it, the query logic will
        // always stop at most one node after the keys diverge, which guarantees that
        // the new trie path will always be shorter if a collapse occurred.
        let branch_collapse_occurred = old_path.0.len() > new_path.0.len();

        // Now we need to determine the key of the only remaining node after the
        // collapse.
        branch_collapse_occurred.then(|| new_path.iter().into_key())
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &HashedPartialTrie,
    state_accesses: impl Iterator<Item = HashedNodeAddr>,
    additional_state_trie_paths_to_not_hash: impl Iterator<Item = Nibbles>,
) -> TraceDecodingResult<HashedPartialTrie> {
    create_trie_subset_wrapped(
        state_trie,
        state_accesses
            .into_iter()
            .map(Nibbles::from_h256_be)
            .chain(additional_state_trie_paths_to_not_hash),
        TrieType::State,
    )
}

// TODO!!!: We really need to be appending the empty storage tries to the base
// trie somewhere else! This is a big hack!
fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    accesses_per_account: impl Iterator<Item = &'a (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    additional_storage_trie_paths_to_not_hash: &HashMap<HashedAccountAddr, Vec<Nibbles>>,
) -> TraceDecodingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
    accesses_per_account
        .map(|(h_addr, mem_accesses)| {
            // Guaranteed to exist due to calling `init_any_needed_empty_storage_tries`
            // earlier on.
            let base_storage_trie = &storage_tries[h_addr];

            let storage_slots_to_not_hash = mem_accesses.iter().cloned().chain(
                additional_storage_trie_paths_to_not_hash
                    .get(h_addr)
                    .into_iter()
                    .flat_map(|slots| slots.iter().cloned()),
            );

            let partial_storage_trie = create_trie_subset_wrapped(
                base_storage_trie,
                storage_slots_to_not_hash,
                TrieType::Storage,
            )?;

            Ok((*h_addr, partial_storage_trie))
        })
        .collect::<TraceDecodingResult<_>>()
}

fn create_trie_subset_wrapped(
    trie: &HashedPartialTrie,
    accesses: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceDecodingResult<HashedPartialTrie> {
    create_trie_subset(trie, accesses).map_err(|trie_err| {
        let key = match trie_err {
            SubsetTrieError::UnexpectedKey(key, _) => key,
        };

        Box::new(TraceDecodingError::new(
            TraceParsingErrorReason::MissingKeysCreatingSubPartialTrie(key, trie_type),
        ))
    })
}

fn account_from_rlped_bytes(bytes: &[u8]) -> TraceDecodingResult<MptAccountRlp> {
    rlp::decode(bytes).map_err(|err| {
        Box::new(TraceDecodingError::new(
            TraceParsingErrorReason::AccountDecode(hex::encode(bytes), err.to_string()),
        ))
    })
}

/// The current state of all tries as we process txn deltas. These are mutated
/// after every txn we process in the trace.
#[derive(Clone, Debug, Default)]
struct PartialTrieState {
    state: HashedPartialTrie,
    storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
    txn: HashedPartialTrie,
    receipt: HashedPartialTrie,
}


impl BlockTrace {
    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn into_proof_gen_mpt_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceProtocolDecodingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_mpt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }

    fn into_mpt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceProtocolDecodingResult<MptProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        self.into_processed_block_trace::<_, MptBlockTraceProcessing, MptProcessedBlockTrace>(p_meta, withdrawals)
    }
}

fn create_minimal_partial_tries_needed_by_txn(
    curr_block_tries: &D::TState,
    nodes_used_by_txn: &NodesUsedByTxn,
    txn_idx: TxnIdx,
    delta_application_out: TrieDeltaApplicationOutput,
    _coin_base_addr: &Address,
) -> TraceDecodingResult<MptTrieInputs> {
    let state_trie = create_minimal_state_partial_trie(
        &curr_block_tries.state,
        nodes_used_by_txn.state_accesses.iter().cloned(),
        delta_application_out
            .additional_state_trie_paths_to_not_hash
            .into_iter(),
    )?;

    let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
    // TODO: Replace cast once `mpt_trie` supports `into` for `usize...
    let transactions_trie =
        create_trie_subset_wrapped(&curr_block_tries.txn, once(txn_k), TrieType::Txn)?;

    let receipts_trie =
        create_trie_subset_wrapped(&curr_block_tries.receipt, once(txn_k), TrieType::Receipt)?;

    let storage_tries = create_minimal_storage_partial_tries(
        &curr_block_tries.storage,
        &nodes_used_by_txn.state_accounts_with_no_accesses_but_storage_tries,
        nodes_used_by_txn.storage_accesses.iter(),
        &delta_application_out.additional_storage_trie_paths_to_not_hash,
    )?;

    Ok(MptTrieInputs {
        state_trie,
        transactions_trie,
        receipts_trie,
        storage_tries,
    })
}
