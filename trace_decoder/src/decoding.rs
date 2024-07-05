use std::{
    cmp::min,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::{self, empty},
    ops::Range,
};

use ethereum_types::{Address, H256, U256, U512};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::{ExtraBlockData, TrieRoots},
};
use log::trace;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    special_query::path_for_query,
    trie_ops::{TrieOpError, TrieOpResult},
    trie_subsets::{create_trie_subset, SubsetTrieError},
    utils::{IntoTrieKey, TriePath},
};
use thiserror::Error;

use crate::{
    compact::compact_prestate_processing::CompactParsingError,
    processed_block_trace::{
        NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo, StateTrieWrites, TxnMetaState,
    },
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, HashedStorageAddrNibbles,
        OtherBlockData, TrieRootHash, TxnIdx, EMPTY_ACCOUNT_BYTES_RLPED,
        ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, optional_field, optional_field_hex, update_val_if_some},
};

/// Stores the result of parsing tries. Returns a [TraceParsingError] upon
/// failure.
pub type TraceParsingResult<T> = Result<T, Box<TraceParsingError>>;

/// Represents errors that can occur during the processing of a block trace.
///
/// This struct is intended to encapsulate various kinds of errors that might
/// arise when parsing, validating, or otherwise processing the trace data of
/// blockchain blocks. It could include issues like malformed trace data,
/// inconsistencies found during processing, or any other condition that
/// prevents successful completion of the trace processing task.
#[derive(Debug)]
pub struct TraceParsingError {
    block_num: Option<U256>,
    block_chain_id: Option<U256>,
    txn_idx: Option<usize>,
    addr: Option<Address>,
    h_addr: Option<H256>,
    slot: Option<U512>,
    slot_value: Option<U512>,
    reason: TraceParsingErrorReason, // The original error type
}

impl std::fmt::Display for TraceParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let h_slot = self.slot.map(|slot| {
            let mut buf = [0u8; 64];
            slot.to_big_endian(&mut buf);
            hash(&buf)
        });
        write!(
            f,
            "Error processing trace: {}\n{}{}{}{}{}{}{}{}",
            self.reason,
            optional_field("Block num", self.block_num),
            optional_field("Block chain id", self.block_chain_id),
            optional_field("Txn idx", self.txn_idx),
            optional_field("Address", self.addr.as_ref()),
            optional_field("Hashed address", self.h_addr.as_ref()),
            optional_field_hex("Slot", self.slot),
            optional_field("Hashed Slot", h_slot),
            optional_field_hex("Slot value", self.slot_value),
        )
    }
}

impl std::error::Error for TraceParsingError {}

impl TraceParsingError {
    /// Function to create a new TraceParsingError with mandatory fields
    pub(crate) fn new(reason: TraceParsingErrorReason) -> Self {
        Self {
            block_num: None,
            block_chain_id: None,
            txn_idx: None,
            addr: None,
            h_addr: None,
            slot: None,
            slot_value: None,
            reason,
        }
    }

    /// Builder method to set block_num
    pub(crate) fn block_num(&mut self, block_num: U256) -> &mut Self {
        self.block_num = Some(block_num);
        self
    }

    /// Builder method to set block_chain_id
    pub(crate) fn block_chain_id(&mut self, block_chain_id: U256) -> &mut Self {
        self.block_chain_id = Some(block_chain_id);
        self
    }

    /// Builder method to set txn_idx
    pub fn txn_idx(&mut self, txn_idx: usize) -> &mut Self {
        self.txn_idx = Some(txn_idx);
        self
    }

    /// Builder method to set addr
    pub fn addr(&mut self, addr: Address) -> &mut Self {
        self.addr = Some(addr);
        self
    }

    /// Builder method to set h_addr
    pub fn h_addr(&mut self, h_addr: H256) -> &mut Self {
        self.h_addr = Some(h_addr);
        self
    }

    /// Builder method to set slot
    pub fn slot(&mut self, slot: U512) -> &mut Self {
        self.slot = Some(slot);
        self
    }

    /// Builder method to set slot_value
    pub fn slot_value(&mut self, slot_value: U512) -> &mut Self {
        self.slot_value = Some(slot_value);
        self
    }
}

/// An error reason for trie parsing.
#[derive(Debug, Error)]
pub enum TraceParsingErrorReason {
    /// Failure to decode an Ethereum Account.
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    /// Failure due to trying to access or delete a storage trie missing
    /// from the base trie.
    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0:x})")]
    MissingAccountStorageTrie(HashedAccountAddr),

    /// Failure due to trying to access a non-existent key in the trie.
    #[error("Tried accessing a non-existent key ({1:x}) in the {0} trie (root hash: {2:x})")]
    NonExistentTrieEntry(TrieType, Nibbles, TrieRootHash),

    /// Failure due to missing keys when creating a sub-partial trie.
    #[error("Missing key {0:x} when creating sub-partial tries (Trie type: {1})")]
    MissingKeysCreatingSubPartialTrie(Nibbles, TrieType),

    /// Failure due to trying to withdraw from a missing account
    #[error("No account present at {0:x} (hashed: {1:x}) to withdraw {2} Gwei from!")]
    MissingWithdrawalAccount(Address, HashedAccountAddr, U256),

    /// Failure due to a trie operation error.
    #[error("Trie operation error: {0}")]
    TrieOpError(TrieOpError),

    /// Failure due to a compact parsing error.
    #[error("Compact parsing error: {0}")]
    CompactParsingError(CompactParsingError),
}

impl From<TrieOpError> for TraceParsingError {
    fn from(err: TrieOpError) -> Self {
        // Convert TrieOpError into TraceParsingError
        TraceParsingError::new(TraceParsingErrorReason::TrieOpError(err))
    }
}

impl From<CompactParsingError> for TraceParsingError {
    fn from(err: CompactParsingError) -> Self {
        // Convert CompactParsingError into TraceParsingError
        TraceParsingError::new(TraceParsingErrorReason::CompactParsingError(err))
    }
}

/// An enum to cover all Ethereum trie types (see <https://ethereum.github.io/yellowpaper/paper.pdf> for details).
#[derive(Debug)]
pub enum TrieType {
    /// State trie.
    State,
    /// Storage trie.
    Storage,
    /// Receipt trie.
    Receipt,
    /// Transaction trie.
    Txn,
}

impl Display for TrieType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TrieType::State => write!(f, "state"),
            TrieType::Storage => write!(f, "storage"),
            TrieType::Receipt => write!(f, "receipt"),
            TrieType::Txn => write!(f, "transaction"),
        }
    }
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

/// Additional information discovered during delta application.
#[derive(Debug, Default)]
struct TrieDeltaApplicationOutput {
    // During delta application, if a delete occurs, we may have to make sure additional nodes
    // that are not accessed by the txn remain unhashed.
    additional_state_trie_paths_to_not_hash: Vec<Nibbles>,
    additional_storage_trie_paths_to_not_hash: HashMap<H256, Vec<Nibbles>>,
}

impl ProcessedBlockTrace {
    pub(crate) fn into_txn_proof_gen_ir(
        self,
        other_data: OtherBlockData,
        batch_size: usize,
    ) -> TraceParsingResult<Vec<GenerationInputs>> {
        let mut curr_block_tries = PartialTrieState {
            state: self.tries.state.clone(),
            storage: self.tries.storage.clone(),
            ..Default::default()
        };

        // This is just a copy of `curr_block_tries`.
        let initial_tries_for_dummies = PartialTrieState {
            state: self.tries.state,
            storage: self.tries.storage,
            ..Default::default()
        };

        let mut extra_data = ExtraBlockData {
            checkpoint_state_trie_root: other_data.checkpoint_state_trie_root,
            txn_number_before: U256::zero(),
            txn_number_after: U256::zero(),
            gas_used_before: U256::zero(),
            gas_used_after: U256::zero(),
        };

        // A copy of the initial extra_data possibly needed during padding.
        let extra_data_for_dummies = extra_data.clone();

        let num_txs = self
            .txn_info
            .iter()
            .map(|tx_info| tx_info.meta.len())
            .sum::<usize>();

        let mut txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, txn_info)| {
                let txn_range =
                    (txn_idx * batch_size)..min(txn_idx * batch_size + batch_size, num_txs);

                Self::process_txn_info(
                    txn_range,
                    txn_info,
                    &mut curr_block_tries,
                    &mut extra_data,
                    &other_data,
                )
                .map_err(|mut e| {
                    e.txn_idx(txn_idx);
                    e
                })
            })
            .collect::<TraceParsingResult<Vec<_>>>()
            .map_err(|mut e| {
                e.block_num(other_data.b_data.b_meta.block_number);
                e.block_chain_id(other_data.b_data.b_meta.block_chain_id);
                e
            })?;

        Self::pad_gen_inputs_with_dummy_inputs_if_needed(
            &mut txn_gen_inputs,
            &other_data,
            &extra_data,
            &extra_data_for_dummies,
            &initial_tries_for_dummies,
            &curr_block_tries,
        );

        if !self.withdrawals.is_empty() {
            Self::add_withdrawals_to_txns(
                &mut txn_gen_inputs,
                &mut curr_block_tries,
                self.withdrawals,
            )?;
        }

        Ok(txn_gen_inputs)
    }

    fn update_txn_and_receipt_tries(
        trie_state: &mut PartialTrieState,
        meta: &TxnMetaState,
        txn_idx: TxnIdx,
    ) -> TrieOpResult<()> {
        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        trie_state.txn.insert(txn_k, meta.txn_bytes())?;

        trie_state
            .receipt
            .insert(txn_k, meta.receipt_node_bytes.as_ref())
    }

    /// If the account does not have a storage trie or does but is not
    /// accessed by any txns, then we still need to manually create an entry for
    /// them.
    fn init_any_needed_empty_storage_tries<'a>(
        storage_tries: &mut HashMap<HashedAccountAddr, HashedPartialTrie>,
        accounts_with_storage: impl Iterator<Item = &'a HashedStorageAddr>,
        state_accounts_with_no_accesses_but_storage_tries: &'a HashMap<
            HashedAccountAddr,
            TrieRootHash,
        >,
    ) {
        for h_addr in accounts_with_storage {
            if !storage_tries.contains_key(h_addr) {
                let trie = state_accounts_with_no_accesses_but_storage_tries
                    .get(h_addr)
                    .map(|s_root| HashedPartialTrie::new(Node::Hash(*s_root)))
                    .unwrap_or_default();

                storage_tries.insert(*h_addr, trie);
            };
        }
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &PartialTrieState,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_range: Range<TxnIdx>,
        delta_application_out: TrieDeltaApplicationOutput,
        _coin_base_addr: &Address,
    ) -> TraceParsingResult<TrieInputs> {
        let state_trie = create_minimal_state_partial_trie(
            &curr_block_tries.state,
            nodes_used_by_txn.state_accesses.iter().cloned(),
            delta_application_out
                .additional_state_trie_paths_to_not_hash
                .into_iter(),
        )?;

        let txn_nibbles =
            txn_range.map(|txn_idx| Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap());

        let transactions_trie =
            create_trie_subset_wrapped(&curr_block_tries.txn, txn_nibbles.clone(), TrieType::Txn)?;

        let receipts_trie =
            create_trie_subset_wrapped(&curr_block_tries.receipt, txn_nibbles, TrieType::Receipt)?;

        let storage_tries = create_minimal_storage_partial_tries(
            &curr_block_tries.storage,
            nodes_used_by_txn.storage_accesses.clone().into_iter(),
            &delta_application_out.additional_storage_trie_paths_to_not_hash,
        )?;

        Ok(TrieInputs {
            state_trie,
            transactions_trie,
            receipts_trie,
            storage_tries,
        })
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: &NodesUsedByTxn,
    ) -> TraceParsingResult<TrieDeltaApplicationOutput> {
        let mut out = TrieDeltaApplicationOutput::default();

        for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
            let storage_trie = trie_state.storage.get_mut(hashed_acc_addr).ok_or_else(|| {
                let hashed_acc_addr = *hashed_acc_addr;
                let mut e = TraceParsingError::new(
                    TraceParsingErrorReason::MissingAccountStorageTrie(hashed_acc_addr),
                );
                e.h_addr(hashed_acc_addr);
                e
            })?;

            for (slot, val) in storage_writes
                .iter()
                .map(|(k, v)| (Nibbles::from_h256_be(hash(&k.bytes_be())), v))
            {
                // If we are writing a zero, then we actually need to perform a delete.
                match val == &ZERO_STORAGE_SLOT_VAL_RLPED {
                    false => storage_trie.insert(slot, val.clone()).map_err(|err| {
                        let mut e =
                            TraceParsingError::new(TraceParsingErrorReason::TrieOpError(err));
                        e.slot(U512::from_big_endian(slot.bytes_be().as_slice()));
                        e.slot_value(U512::from_big_endian(val.as_slice()));
                        e
                    })?,
                    true => {
                        if let Some(remaining_slot_key) =
                            Self::delete_node_and_report_remaining_key_if_branch_collapsed(
                                storage_trie,
                                &slot,
                            )
                            .map_err(TraceParsingError::from)?
                        {
                            out.additional_storage_trie_paths_to_not_hash
                                .entry(*hashed_acc_addr)
                                .or_default()
                                .push(remaining_slot_key);
                        }
                    }
                };
            }
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.state_writes.iter() {
            let val_k = Nibbles::from_h256_be(*hashed_acc_addr);

            // If the account was created, then it will not exist in the trie.
            let val_bytes = trie_state
                .state
                .get(val_k)
                .unwrap_or(&EMPTY_ACCOUNT_BYTES_RLPED);

            let mut account = account_from_rlped_bytes(val_bytes)?;

            s_trie_writes.apply_writes_to_state_node(
                &mut account,
                hashed_acc_addr,
                &trie_state.storage,
            )?;

            let updated_account_bytes = rlp::encode(&account);
            trie_state
                .state
                .insert(val_k, updated_account_bytes.to_vec())
                .map_err(TraceParsingError::from)?;
        }

        // Remove any accounts that self-destructed.
        for hashed_addr in deltas.self_destructed_accounts.iter() {
            let k = Nibbles::from_h256_be(*hashed_addr);

            trie_state.storage.remove(hashed_addr).ok_or_else(|| {
                let hashed_addr = *hashed_addr;
                let mut e = TraceParsingError::new(
                    TraceParsingErrorReason::MissingAccountStorageTrie(hashed_addr),
                );
                e.h_addr(hashed_addr);
                e
            })?;

            // TODO: Once the mechanism for resolving code hashes settles, we probably want
            // to also delete the code hash mapping here as well...

            if let Some(remaining_account_key) =
                Self::delete_node_and_report_remaining_key_if_branch_collapsed(
                    &mut trie_state.state,
                    &k,
                )
                .map_err(TraceParsingError::from)?
            {
                out.additional_state_trie_paths_to_not_hash
                    .push(remaining_account_key);
            }
        }

        Ok(out)
    }

    fn get_trie_trace(trie: &HashedPartialTrie, k: &Nibbles) -> TriePath {
        path_for_query(trie, *k, true).collect()
    }

    /// If a branch collapse occurred after a delete, then we must ensure that
    /// the other single child that remains also is not hashed when passed into
    /// plonky2. Returns the key to the remaining child if a collapse occurred.
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

    /// Pads a generated IR vec with additional "dummy" entries if needed.
    /// We need to ensure that generated IR always has at least `2` elements,
    /// and if there are only `0` or `1` elements, then we need to pad so
    /// that we have two entries in total. These dummy entries serve only to
    /// allow the proof generation process to finish. Specifically, we need
    /// at least two entries to generate an agg proof, and we need an agg
    /// proof to generate a block proof. These entries do not mutate state.
    fn pad_gen_inputs_with_dummy_inputs_if_needed(
        gen_inputs: &mut Vec<GenerationInputs>,
        other_data: &OtherBlockData,
        final_extra_data: &ExtraBlockData,
        initial_extra_data: &ExtraBlockData,
        initial_tries: &PartialTrieState,
        final_tries: &PartialTrieState,
    ) {
        match gen_inputs.len() {
            0 => {
                debug_assert!(initial_tries.state == final_tries.state);
                debug_assert!(initial_extra_data == final_extra_data);
                // We need to pad with two dummy entries.
                gen_inputs.extend(create_dummy_txn_pair_for_empty_block(
                    other_data,
                    final_extra_data,
                    initial_tries,
                ));
            }
            1 => {
                // We just need one dummy entry.
                // The dummy proof will be prepended to the actual txn.
                let dummy_txn =
                    create_dummy_gen_input(other_data, initial_extra_data, initial_tries);
                gen_inputs.insert(0, dummy_txn)
            }
            _ => (),
        }
    }

    /// The withdrawals are always in the final ir payload.
    fn add_withdrawals_to_txns(
        txn_ir: &mut [GenerationInputs],
        final_trie_state: &mut PartialTrieState,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceParsingResult<()> {
        let withdrawals_with_hashed_addrs_iter = || {
            withdrawals
                .iter()
                .map(|(addr, v)| (*addr, hash(addr.as_bytes()), *v))
        };

        let last_inputs = txn_ir
            .last_mut()
            .expect("We cannot have an empty list of payloads.");

        if last_inputs.signed_txns.is_empty() {
            // This is a dummy payload, hence it does not contain yet
            // state accesses to the withdrawal addresses.
            let withdrawal_addrs =
                withdrawals_with_hashed_addrs_iter().map(|(_, h_addr, _)| h_addr);
            last_inputs.tries.state_trie = create_minimal_state_partial_trie(
                &final_trie_state.state,
                withdrawal_addrs,
                iter::empty(),
            )?;
        }

        Self::update_trie_state_from_withdrawals(
            withdrawals_with_hashed_addrs_iter(),
            &mut final_trie_state.state,
        )?;

        last_inputs.withdrawals = withdrawals;
        last_inputs.trie_roots_after.state_root = final_trie_state.state.hash();

        Ok(())
    }

    /// Withdrawals update balances in the account trie, so we need to update
    /// our local trie state.
    fn update_trie_state_from_withdrawals<'a>(
        withdrawals: impl IntoIterator<Item = (Address, HashedAccountAddr, U256)> + 'a,
        state: &mut HashedPartialTrie,
    ) -> TraceParsingResult<()> {
        for (addr, h_addr, amt) in withdrawals {
            let h_addr_nibs = Nibbles::from_h256_be(h_addr);

            let acc_bytes = state.get(h_addr_nibs).ok_or_else(|| {
                let mut e = TraceParsingError::new(
                    TraceParsingErrorReason::MissingWithdrawalAccount(addr, h_addr, amt),
                );
                e.addr(addr);
                e.h_addr(h_addr);
                e
            })?;
            let mut acc_data = account_from_rlped_bytes(acc_bytes)?;

            acc_data.balance += amt;

            state
                .insert(h_addr_nibs, rlp::encode(&acc_data).to_vec())
                .map_err(TraceParsingError::from)?;
        }

        Ok(())
    }

    /// Processes a single transaction in the trace.
    fn process_txn_info(
        txn_range: Range<TxnIdx>,
        txn_info: ProcessedTxnInfo,
        curr_block_tries: &mut PartialTrieState,
        extra_data: &mut ExtraBlockData,
        other_data: &OtherBlockData,
    ) -> TraceParsingResult<GenerationInputs> {
        trace!(
            "Generating proof IR for txn {} through {}...",
            txn_range.start,
            txn_range.end - 1
        );

        Self::init_any_needed_empty_storage_tries(
            &mut curr_block_tries.storage,
            txn_info.nodes_used_by_txn.storage_accesses.keys(),
            &txn_info
                .nodes_used_by_txn
                .state_accounts_with_no_accesses_but_storage_tries,
        );
        // For each non-dummy txn, we increment `txn_number_after` by 1, and
        // update `gas_used_after` accordingly.
        extra_data.txn_number_after += txn_info.meta.len().into();
        extra_data.gas_used_after += txn_info.meta.iter().map(|i| i.gas_used).sum::<u64>().into();

        // Because we need to run delta application before creating the minimal
        // sub-tries (we need to detect if deletes collapsed any branches), we need to
        // do this clone every iteration.
        let tries_at_start_of_txn = curr_block_tries.clone();

        for (i, meta) in txn_info.meta.iter().enumerate() {
            Self::update_txn_and_receipt_tries(
                curr_block_tries,
                meta,
                extra_data.txn_number_before.as_usize() + i,
            )
            .map_err(TraceParsingError::from)?;
        }

        let delta_out =
            Self::apply_deltas_to_trie_state(curr_block_tries, &txn_info.nodes_used_by_txn)?;

        let tries = Self::create_minimal_partial_tries_needed_by_txn(
            &tries_at_start_of_txn,
            &txn_info.nodes_used_by_txn,
            txn_range,
            delta_out,
            &other_data.b_data.b_meta.block_beneficiary,
        )?;

        let trie_roots_after = calculate_trie_input_hashes(curr_block_tries);
        let gen_inputs = GenerationInputs {
            txn_number_before: extra_data.txn_number_before,
            gas_used_before: extra_data.gas_used_before,
            gas_used_after: extra_data.gas_used_after,
            signed_txns: txn_info
                .meta
                .iter()
                .filter(|t| t.txn_bytes.is_some())
                .map(|tx| tx.txn_bytes())
                .collect::<Vec<_>>(),
            withdrawals: Vec::default(), /* Only ever set in a
                                          * dummy txn
                                          * at the end of
                                          * the block (see `[add_withdrawals_to_txns]`
                                          * for more info). */
            tries,
            trie_roots_after,
            checkpoint_state_trie_root: extra_data.checkpoint_state_trie_root,
            contract_code: txn_info.contract_code_accessed,
            block_metadata: other_data.b_data.b_meta.clone(),
            block_hashes: other_data.b_data.b_hashes.clone(),
        };

        // After processing a transaction, we update the remaining accumulators
        // for the next transaction.
        extra_data.txn_number_before = extra_data.txn_number_after;
        extra_data.gas_used_before = extra_data.gas_used_after;

        Ok(gen_inputs)
    }
}

impl StateTrieWrites {
    fn apply_writes_to_state_node(
        &self,
        state_node: &mut AccountRlp,
        h_addr: &HashedAccountAddr,
        acc_storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    ) -> TraceParsingResult<()> {
        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = acc_storage_tries.get(h_addr).ok_or_else(|| {
                    let h_addr = *h_addr;
                    let mut e = TraceParsingError::new(
                        TraceParsingErrorReason::MissingAccountStorageTrie(h_addr),
                    );
                    e.h_addr(h_addr);
                    e
                })?;

                Some(storage_trie.hash())
            }
        };

        update_val_if_some(&mut state_node.balance, self.balance);
        update_val_if_some(&mut state_node.nonce, self.nonce);
        update_val_if_some(&mut state_node.storage_root, storage_root_hash_change);
        update_val_if_some(&mut state_node.code_hash, self.code_hash);

        Ok(())
    }
}

fn calculate_trie_input_hashes(t_inputs: &PartialTrieState) -> TrieRoots {
    TrieRoots {
        state_root: t_inputs.state.hash(),
        transactions_root: t_inputs.txn.hash(),
        receipts_root: t_inputs.receipt.hash(),
    }
}

// We really want to get a trie with just a hash node here, and this is an easy
// way to do it.
fn create_fully_hashed_out_sub_partial_trie(trie: &HashedPartialTrie) -> HashedPartialTrie {
    // Impossible to actually fail with an empty iter.
    create_trie_subset(trie, empty::<Nibbles>()).unwrap()
}

fn create_dummy_txn_pair_for_empty_block(
    other_data: &OtherBlockData,
    extra_data: &ExtraBlockData,
    final_tries: &PartialTrieState,
) -> [GenerationInputs; 2] {
    [
        create_dummy_gen_input(other_data, extra_data, final_tries),
        create_dummy_gen_input(other_data, extra_data, final_tries),
    ]
}

fn create_dummy_gen_input(
    other_data: &OtherBlockData,
    extra_data: &ExtraBlockData,
    final_tries: &PartialTrieState,
) -> GenerationInputs {
    let sub_tries = create_dummy_proof_trie_inputs(
        final_tries,
        create_fully_hashed_out_sub_partial_trie(&final_tries.state),
    );
    create_dummy_gen_input_common(other_data, extra_data, sub_tries)
}

fn create_dummy_gen_input_common(
    other_data: &OtherBlockData,
    extra_data: &ExtraBlockData,
    sub_tries: TrieInputs,
) -> GenerationInputs {
    let trie_roots_after = TrieRoots {
        state_root: sub_tries.state_trie.hash(),
        transactions_root: sub_tries.transactions_trie.hash(),
        receipts_root: sub_tries.receipts_trie.hash(),
    };

    // Sanity checks
    assert_eq!(
        extra_data.txn_number_before, extra_data.txn_number_after,
        "Txn numbers before/after differ in a dummy payload with no txn!"
    );
    assert_eq!(
        extra_data.gas_used_before, extra_data.gas_used_after,
        "Gas used before/after differ in a dummy payload with no txn!"
    );

    GenerationInputs {
        signed_txns: vec![],
        tries: sub_tries,
        trie_roots_after,
        checkpoint_state_trie_root: extra_data.checkpoint_state_trie_root,
        block_metadata: other_data.b_data.b_meta.clone(),
        block_hashes: other_data.b_data.b_hashes.clone(),
        txn_number_before: extra_data.txn_number_before,
        gas_used_before: extra_data.gas_used_before,
        gas_used_after: extra_data.gas_used_after,
        contract_code: HashMap::default(),
        withdrawals: vec![], // this is set after creating dummy payloads
    }
}

fn create_dummy_proof_trie_inputs(
    final_tries_at_end_of_block: &PartialTrieState,
    state_trie: HashedPartialTrie,
) -> TrieInputs {
    let partial_sub_storage_tries: Vec<_> = final_tries_at_end_of_block
        .storage
        .iter()
        .map(|(hashed_acc_addr, s_trie)| {
            (
                *hashed_acc_addr,
                create_fully_hashed_out_sub_partial_trie(s_trie),
            )
        })
        .collect();

    TrieInputs {
        state_trie,
        transactions_trie: create_fully_hashed_out_sub_partial_trie(
            &final_tries_at_end_of_block.txn,
        ),
        receipts_trie: create_fully_hashed_out_sub_partial_trie(
            &final_tries_at_end_of_block.receipt,
        ),
        storage_tries: partial_sub_storage_tries,
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &HashedPartialTrie,
    state_accesses: impl Iterator<Item = HashedNodeAddr>,
    additional_state_trie_paths_to_not_hash: impl Iterator<Item = Nibbles>,
) -> TraceParsingResult<HashedPartialTrie> {
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
fn create_minimal_storage_partial_tries(
    storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    accesses_per_account: impl Iterator<Item = (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    additional_storage_trie_paths_to_not_hash: &HashMap<HashedAccountAddr, Vec<Nibbles>>,
) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
    accesses_per_account
        .map(|(h_addr, mem_accesses)| {
            // Guaranteed to exist due to calling `init_any_needed_empty_storage_tries`
            // earlier on.
            let base_storage_trie = &storage_tries[&h_addr];

            let storage_slots_to_not_hash = mem_accesses.iter().cloned().chain(
                additional_storage_trie_paths_to_not_hash
                    .get(&h_addr)
                    .into_iter()
                    .flat_map(|slots| slots.iter().cloned()),
            );

            let partial_storage_trie = create_trie_subset_wrapped(
                base_storage_trie,
                storage_slots_to_not_hash,
                TrieType::Storage,
            )?;

            Ok((h_addr, partial_storage_trie))
        })
        .collect::<TraceParsingResult<_>>()
}

fn create_trie_subset_wrapped(
    trie: &HashedPartialTrie,
    accesses: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceParsingResult<HashedPartialTrie> {
    create_trie_subset(trie, accesses).map_err(|trie_err| {
        let key = match trie_err {
            SubsetTrieError::UnexpectedKey(key, _) => key,
        };

        Box::new(TraceParsingError::new(
            TraceParsingErrorReason::MissingKeysCreatingSubPartialTrie(key, trie_type),
        ))
    })
}

fn account_from_rlped_bytes(bytes: &[u8]) -> TraceParsingResult<AccountRlp> {
    rlp::decode(bytes).map_err(|err| {
        Box::new(TraceParsingError::new(
            TraceParsingErrorReason::AccountDecode(hex::encode(bytes), err.to_string()),
        ))
    })
}

impl TxnMetaState {
    fn txn_bytes(&self) -> Vec<u8> {
        match self.txn_bytes.as_ref() {
            Some(v) => v.clone(),
            None => Vec::default(),
        }
    }
}
