use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::{self, empty, once},
};

use ethereum_types::{Address, H256, U256};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::{ExtraBlockData, TrieRoots},
};
use log::trace;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    special_query::path_for_query,
    trie_subsets::create_trie_subset,
    utils::{IntoTrieKey, TriePath, TrieSegment},
};
use thiserror::Error;

use crate::{
    processed_block_trace::{NodesUsedByTxn, ProcessedBlockTrace, StateTrieWrites, TxnMetaState},
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, HashedStorageAddrNibbles,
        OtherBlockData, TriePathIter, TrieRootHash, TxnIdx, TxnProofGenIR,
        EMPTY_ACCOUNT_BYTES_RLPED, ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, update_val_if_some},
};

/// Stores the result of parsing tries. Returns a [TraceParsingError] upon
/// failure.
pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

/// An error type for trie parsing.
#[derive(Debug, Error)]
pub enum TraceParsingError {
    /// Failure to decode an Ethereum [Account].
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    /// Failure due to trying to access or delete a storage trie missing
    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0:x})")]
    /// from the base trie.
    MissingAccountStorageTrie(HashedAccountAddr),

    /// Failure due to trying to access a non-existent key in the trie.
    #[error("Tried accessing a non-existent key ({1:x}) in the {0} trie (root hash: {2:x})")]
    NonExistentTrieEntry(TrieType, Nibbles, TrieRootHash),

    /// Failure due to missing keys when creating a subpartial trie.
    // TODO: Figure out how to make this error useful/meaningful... For now this is just a
    // placeholder.
    #[error("Missing keys when creating sub-partial tries (Trie type: {0})")]
    MissingKeysCreatingSubPartialTrie(TrieType),

    /// Failure due to trying to withdraw from a missing account
    #[error("No account present at {0:x} (hashed: {1:x}) to withdraw {2} Gwei from!")]
    MissingWithdrawalAccount(Address, HashedAccountAddr, U256),
}

/// An enum to cover all Ethereum trie types (see https://ethereum.github.io/yellowpaper/paper.pdf for details).
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
    // remain unhashed that are not accessed by the txn.
    additional_state_trie_paths_to_not_hash: Vec<Nibbles>,
    additional_storage_trie_paths_to_not_hash: HashMap<H256, Vec<Nibbles>>,
}

impl ProcessedBlockTrace {
    pub(crate) fn into_txn_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> TraceParsingResult<Vec<TxnProofGenIR>> {
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

        let mut txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, txn_info)| {
                trace!("Generating proof IR for txn {}...", txn_idx);

                Self::init_any_needed_empty_storage_tries(
                    &mut curr_block_tries.storage,
                    txn_info
                        .nodes_used_by_txn
                        .storage_accesses
                        .iter()
                        .map(|(k, _)| k),
                    &txn_info
                        .nodes_used_by_txn
                        .state_accounts_with_no_accesses_but_storage_tries,
                );
                // For each non-dummy txn, we increment `txn_number_after` by 1, and
                // update `gas_used_after` accordingly.
                extra_data.txn_number_after += U256::one();
                extra_data.gas_used_after += txn_info.meta.gas_used.into();

                // Because we need to run delta application before creating the minimal
                // sub-tries (we need to detect if deletes collapsed any branches), we need to
                // do this clone every iteration.
                let tries_at_start_of_txn = curr_block_tries.clone();

                Self::update_txn_and_receipt_tries(&mut curr_block_tries, &txn_info.meta, txn_idx);

                let delta_out = Self::apply_deltas_to_trie_state(
                    &mut curr_block_tries,
                    &txn_info.nodes_used_by_txn,
                    &txn_info.meta,
                )?;

                let tries = Self::create_minimal_partial_tries_needed_by_txn(
                    &tries_at_start_of_txn,
                    &txn_info.nodes_used_by_txn,
                    txn_idx,
                    delta_out,
                    &other_data.b_data.b_meta.block_beneficiary,
                )?;

                let trie_roots_after = calculate_trie_input_hashes(&curr_block_tries);
                let gen_inputs = GenerationInputs {
                    txn_number_before: extra_data.txn_number_before,
                    gas_used_before: extra_data.gas_used_before,
                    gas_used_after: extra_data.gas_used_after,
                    signed_txn: txn_info.meta.txn_bytes,
                    withdrawals: Vec::default(), /* Only ever set in a dummy txn at the end of
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
                extra_data.txn_number_before += U256::one();
                extra_data.gas_used_before = extra_data.gas_used_after;

                Ok(gen_inputs)
            })
            .collect::<TraceParsingResult<Vec<_>>>()?;

        let dummies_added = Self::pad_gen_inputs_with_dummy_inputs_if_needed(
            &mut txn_gen_inputs,
            &other_data,
            &extra_data,
            &extra_data_for_dummies,
            &initial_tries_for_dummies,
            &curr_block_tries,
            !self.withdrawals.is_empty(),
        );

        if !self.withdrawals.is_empty() {
            Self::add_withdrawals_to_txns(
                &mut txn_gen_inputs,
                &other_data,
                &extra_data,
                &mut curr_block_tries,
                self.withdrawals,
                dummies_added,
            )?;
        }

        Ok(txn_gen_inputs)
    }

    fn update_txn_and_receipt_tries(
        trie_state: &mut PartialTrieState,
        meta: &TxnMetaState,
        txn_idx: TxnIdx,
    ) {
        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        trie_state.txn.insert(txn_k, meta.txn_bytes());

        trie_state
            .receipt
            .insert(txn_k, meta.receipt_node_bytes.as_ref());
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
        txn_idx: TxnIdx,
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
        meta: &TxnMetaState,
    ) -> TraceParsingResult<TrieDeltaApplicationOutput> {
        let mut out = TrieDeltaApplicationOutput::default();

        for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
            let mut storage_trie = trie_state.storage.get_mut(hashed_acc_addr).ok_or(
                TraceParsingError::MissingAccountStorageTrie(*hashed_acc_addr),
            )?;

            for (slot, val) in storage_writes.iter().map(|(k, v)| (k, v)) {
                // If we are writing a zero, then we actually need to perform a delete.
                match val == &ZERO_STORAGE_SLOT_VAL_RLPED {
                    false => storage_trie.insert(*slot, val.clone()),
                    true => {
                        if let Some(remaining_slot_key) =
                            Self::delete_node_and_report_remaining_key_if_branch_collapsed(
                                storage_trie,
                                slot,
                            )
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
                .insert(val_k, updated_account_bytes.to_vec());
        }

        // Remove any accounts that self-destructed.
        for hashed_addr in deltas.self_destructed_accounts.iter() {
            let k = Nibbles::from_h256_be(*hashed_addr);

            trie_state
                .storage
                .remove(hashed_addr)
                .ok_or(TraceParsingError::MissingAccountStorageTrie(*hashed_addr))?;

            // TODO: Once the mechanism for resolving code hashes settles, we probably want
            // to also delete the code hash mapping here as well...

            if let Some(remaining_account_key) =
                Self::delete_node_and_report_remaining_key_if_branch_collapsed(
                    &mut trie_state.state,
                    &k,
                )
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
    /// plonky2. Returns the key to the remaining child if a collapse occured.
    fn delete_node_and_report_remaining_key_if_branch_collapsed(
        trie: &mut HashedPartialTrie,
        delete_k: &Nibbles,
    ) -> Option<Nibbles> {
        let old_trace = Self::get_trie_trace(trie, delete_k);
        trie.delete(*delete_k);
        let new_trace = Self::get_trie_trace(trie, delete_k);

        Self::node_deletion_resulted_in_a_branch_collapse(&old_trace, &new_trace)
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

        // If a collapse occurred, then this means that the node above the leaf has
        // changed type. However, there are only two possibilities:
        // Note that this function assumes that the delete always succeeds (which the
        //
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
    /// proof to generate a block proof. These entries do not mutate state
    /// (unless there are withdrawals in the block (see
    /// `[add_withdrawals_to_txns]`), where the final one will mutate the
    /// state trie.
    fn pad_gen_inputs_with_dummy_inputs_if_needed(
        gen_inputs: &mut Vec<TxnProofGenIR>,
        other_data: &OtherBlockData,
        final_extra_data: &ExtraBlockData,
        initial_extra_data: &ExtraBlockData,
        initial_tries: &PartialTrieState,
        final_tries: &PartialTrieState,
        has_withdrawals: bool,
    ) -> bool {
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

                true
            }
            1 => {
                // We just need one dummy entry.
                // If there are withdrawals, we will need to append them at the end of the block
                // execution, in which case we directly append the dummy proof
                // after the only txn of this block.
                // If there are no withdrawals, then the dummy proof will be prepended to the
                // actual txn.
                match has_withdrawals {
                    false => {
                        let dummy_txn =
                            create_dummy_gen_input(other_data, initial_extra_data, initial_tries);
                        gen_inputs.insert(0, dummy_txn)
                    }
                    true => {
                        let dummy_txn =
                            create_dummy_gen_input(other_data, final_extra_data, final_tries);
                        gen_inputs.push(dummy_txn)
                    }
                };

                true
            }
            _ => false,
        }
    }

    /// The withdrawals are always in the final ir payload. How they are placed
    /// differs based on whether or not there are already dummy proofs present
    /// in the IR. The rules for adding withdrawals to the IR list are:
    /// - If dummy proofs are already present, then the withdrawals are added to
    ///   the last dummy proof (always index `1`).
    /// - If no dummy proofs are already present, then a dummy proof that just
    ///   contains the withdrawals is appended to the end of the IR vec.
    fn add_withdrawals_to_txns(
        txn_ir: &mut Vec<TxnProofGenIR>,
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_trie_state: &mut PartialTrieState,
        withdrawals: Vec<(Address, U256)>,
        dummies_already_added: bool,
    ) -> TraceParsingResult<()> {
        let withdrawals_with_hashed_addrs_iter = withdrawals
            .iter()
            .map(|(addr, v)| (*addr, hash(addr.as_bytes()), *v));

        match dummies_already_added {
            // If we have no actual dummy proofs, then we create one and append it to the
            // end of the block.
            false => {
                // TODO: Decide if we want this allocation...
                // To avoid double hashing the addrs, but I don't know if the extra `Vec`
                // allocation is worth it.
                let withdrawals_with_hashed_addrs: Vec<_> =
                    withdrawals_with_hashed_addrs_iter.collect();

                // Dummy state will be the state after the final txn. Also need to include the
                // account nodes that were accessed by the withdrawals.
                let withdrawal_addrs = withdrawals_with_hashed_addrs
                    .iter()
                    .cloned()
                    .map(|(_, h_addr, _)| h_addr);
                let mut withdrawal_dummy = create_dummy_gen_input_with_state_addrs_accessed(
                    other_data,
                    extra_data,
                    final_trie_state,
                    withdrawal_addrs,
                )?;

                Self::update_trie_state_from_withdrawals(
                    withdrawals_with_hashed_addrs,
                    &mut final_trie_state.state,
                )?;

                withdrawal_dummy.withdrawals = withdrawals;

                // Only the state root hash needs to be updated from the withdrawals.
                withdrawal_dummy.trie_roots_after.state_root = final_trie_state.state.hash();

                txn_ir.push(withdrawal_dummy);
            }
            true => {
                Self::update_trie_state_from_withdrawals(
                    withdrawals_with_hashed_addrs_iter,
                    &mut final_trie_state.state,
                )?;

                // If we have dummy proofs (note: `txn_ir[1]` is always a dummy txn in this
                // case), then this dummy will get the withdrawals.
                txn_ir[1].withdrawals = withdrawals;
                txn_ir[1].trie_roots_after.state_root = final_trie_state.state.hash();
            }
        }

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

            let acc_bytes =
                state
                    .get(h_addr_nibs)
                    .ok_or(TraceParsingError::MissingWithdrawalAccount(
                        addr, h_addr, amt,
                    ))?;
            let mut acc_data = account_from_rlped_bytes(acc_bytes)?;

            acc_data.balance += amt;

            state.insert(h_addr_nibs, rlp::encode(&acc_data).to_vec());
        }

        Ok(())
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
                let storage_trie = acc_storage_tries
                    .get(h_addr)
                    .ok_or(TraceParsingError::MissingAccountStorageTrie(*h_addr))?;

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
) -> [TxnProofGenIR; 2] {
    [
        create_dummy_gen_input(other_data, extra_data, final_tries),
        create_dummy_gen_input(other_data, extra_data, final_tries),
    ]
}

fn create_dummy_gen_input(
    other_data: &OtherBlockData,
    extra_data: &ExtraBlockData,
    final_tries: &PartialTrieState,
) -> TxnProofGenIR {
    let sub_tries = create_dummy_proof_trie_inputs(
        final_tries,
        create_fully_hashed_out_sub_partial_trie(&final_tries.state),
    );
    create_dummy_gen_input_common(other_data, extra_data, sub_tries)
}

fn create_dummy_gen_input_with_state_addrs_accessed(
    other_data: &OtherBlockData,
    extra_data: &ExtraBlockData,
    final_tries: &PartialTrieState,
    account_addrs_accessed: impl Iterator<Item = HashedAccountAddr>,
) -> TraceParsingResult<TxnProofGenIR> {
    let sub_tries = create_dummy_proof_trie_inputs(
        final_tries,
        create_minimal_state_partial_trie(
            &final_tries.state,
            account_addrs_accessed,
            iter::empty(),
        )?,
    );
    Ok(create_dummy_gen_input_common(
        other_data, extra_data, sub_tries,
    ))
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
        signed_txn: None,
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
fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    state_accounts_with_no_accesses_but_storage_tries: &HashMap<HashedAccountAddr, TrieRootHash>,
    accesses_per_account: impl Iterator<Item = &'a (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    additional_storage_trie_paths_to_not_hash: &HashMap<HashedAccountAddr, Vec<Nibbles>>,
) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
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
        .collect::<TraceParsingResult<_>>()
}

fn create_trie_subset_wrapped(
    trie: &HashedPartialTrie,
    accesses: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceParsingResult<HashedPartialTrie> {
    create_trie_subset(trie, accesses)
        .map_err(|_| TraceParsingError::MissingKeysCreatingSubPartialTrie(trie_type))
}

fn account_from_rlped_bytes(bytes: &[u8]) -> TraceParsingResult<AccountRlp> {
    rlp::decode(bytes)
        .map_err(|err| TraceParsingError::AccountDecode(hex::encode(bytes), err.to_string()))
}

impl TxnMetaState {
    fn txn_bytes(&self) -> Vec<u8> {
        match self.txn_bytes.as_ref() {
            Some(v) => v.clone(),
            None => Vec::default(),
        }
    }
}
