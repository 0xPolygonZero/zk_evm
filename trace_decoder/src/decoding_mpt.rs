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
    },
    compact::compact_mpt_processing::MptPartialTriePreImages,
    decoding::{
        TraceDecodingError, TraceDecodingResult, TraceParsingError, TraceParsingErrorReason,
        TrieType,
    },
    processed_block_trace::{
        NodesUsedByTxn, ProcessedSectionInfo, ProcessedSectionTxnInfo, StateTrieWrites,
    },
    processed_block_trace_mpt::MptProcessedBlockTrace,
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, HashedStorageAddrNibbles,
        OtherBlockData, TrieRootHash, TxnIdx, EMPTY_ACCOUNT_BYTES_RLPED,
        ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, update_val_if_some},
};

// TODO: Make a final decision if we need a separate error for MPT...
pub(crate) type MptTraceParsingError = TraceParsingError;

impl MptProcessedBlockTrace {
    pub(crate) fn into_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<MptGenerationInputs>> {
        match self.spec.sect_info {
            ProcessedSectionInfo::Continuations(_) => {
                todo!("MPT continuations are not implemented yet!")
            }
            ProcessedSectionInfo::Txns(txns) => {
                Self::process_txns(txns, self.spec.tries, self.withdrawals, &other_data)
            }
        }
    }

    fn process_txns(
        txns: Vec<ProcessedSectionTxnInfo>,
        tries: MptPartialTriePreImages,
        withdrawals: Vec<(Address, U256)>,
        other_data: &OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>> {
        let mut curr_block_tries = PartialTrieState {
            state: tries.state.clone(),
            storage: tries.storage.clone(),
            ..Default::default()
        };

        // This is just a copy of `curr_block_tries`.
        let initial_tries_for_dummies = PartialTrieState {
            state: tries.state.clone(),
            storage: tries.storage.clone(),
            ..Default::default()
        };

        let mut extra_data = MptExtraBlockData {
            checkpoint_state_trie_root: other_data.checkpoint_state_trie_root,
            txn_number_before: U256::zero(),
            txn_number_after: U256::zero(),
            gas_used_before: U256::zero(),
            gas_used_after: U256::zero(),
        };

        // A copy of the initial extra_data possibly needed during padding.
        let extra_data_for_dummies = extra_data.clone();

        let mut ir = txns
            .into_iter()
            .enumerate()
            .map(|(txn_idx, sect_info)| {
                Self::process_txn_info(
                    txn_idx,
                    sect_info,
                    &mut curr_block_tries,
                    &mut extra_data,
                    other_data,
                )
                .map_err(|mut e| {
                    e.txn_idx(txn_idx);
                    e
                })
            })
            .collect::<TraceDecodingResult<_>>()
            .map_err(|mut e| {
                e.block_num(other_data.b_data.b_meta.block_number);
                e.block_chain_id(other_data.b_data.b_meta.block_chain_id);
                e
            })?;

        Self::pad_gen_inputs_with_dummy_inputs_if_needed(
            &mut ir,
            other_data,
            &extra_data,
            &extra_data_for_dummies,
            &initial_tries_for_dummies,
            &curr_block_tries,
        );

        if !withdrawals.is_empty() {
            Self::add_withdrawals_to_txns(&mut ir, &mut curr_block_tries, withdrawals.clone())?;
        }

        Ok(ir)
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
            .map_err(TrieOpError::from)
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

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: &NodesUsedByTxn,
    ) -> TraceDecodingResult<TrieDeltaApplicationOutput> {
        let mut out: TrieDeltaApplicationOutput = TrieDeltaApplicationOutput::default();

        for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
            let storage_trie = trie_state.storage.get_mut(hashed_acc_addr).ok_or_else(|| {
                let hashed_acc_addr = *hashed_acc_addr;
                let mut e = TraceDecodingError::new(
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
                            TraceDecodingError::new(TraceParsingErrorReason::TrieOpError(err));
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
                            .map_err(TraceDecodingError::from)?
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
                .map_err(TraceDecodingError::from)?;
        }

        // Remove any accounts that self-destructed.
        for hashed_addr in deltas.self_destructed_accounts.iter() {
            let k = Nibbles::from_h256_be(*hashed_addr);

            trie_state.storage.remove(hashed_addr).ok_or_else(|| {
                let hashed_addr = *hashed_addr;
                let mut e = TraceDecodingError::new(
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
                .map_err(TraceDecodingError::from)?
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
        final_extra_data: &MptExtraBlockData,
        initial_extra_data: &MptExtraBlockData,
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
    ) -> TraceDecodingResult<()> {
        let withdrawals_with_hashed_addrs_iter = || {
            withdrawals
                .iter()
                .map(|(addr, v)| (*addr, hash(addr.as_bytes()), *v))
        };

        let last_inputs = txn_ir
            .last_mut()
            .expect("We cannot have an empty list of payloads.");

        if last_inputs.signed_txn.is_none() {
            // This is a dummy payload, hence it does not contain yet
            // state accesses to the withdrawal addresses.
            let withdrawal_addrs =
                withdrawals_with_hashed_addrs_iter().map(|(_, h_addr, _)| h_addr);
            last_inputs.tries.state_trie = create_minimal_state_partial_trie(
                &last_inputs.tries.state_trie,
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
    ) -> TraceDecodingResult<()> {
        for (addr, h_addr, amt) in withdrawals {
            let h_addr_nibs = Nibbles::from_h256_be(h_addr);

            let acc_bytes = state.get(h_addr_nibs).ok_or_else(|| {
                let mut e = TraceDecodingError::new(
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
                .map_err(TraceDecodingError::from)?;
        }

        Ok(())
    }

    /// Processes a single transaction in the trace.
    fn process_txn_info(
        txn_idx: usize,
        txn_info: ProcessedSectionTxnInfo,
        curr_block_tries: &mut PartialTrieState,
        extra_data: &mut MptExtraBlockData,
        other_data: &OtherBlockData,
    ) -> TraceDecodingResult<GenerationInputs> {
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

        Self::update_txn_and_receipt_tries(curr_block_tries, &txn_info.meta, txn_idx)
            .map_err(TraceDecodingError::from)?;

        let delta_out =
            Self::apply_deltas_to_trie_state(curr_block_tries, &txn_info.nodes_used_by_txn)?;

        let tries = Self::create_minimal_partial_tries_needed_by_txn(
            &tries_at_start_of_txn,
            &txn_info.nodes_used_by_txn,
            txn_idx,
            delta_out,
            &other_data.b_data.b_meta.block_beneficiary,
        )?;

        let trie_roots_after = calculate_trie_input_hashes(curr_block_tries);
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
    }
}

impl StateTrieWrites {
    fn apply_writes_to_state_node(
        &self,
        state_node: &mut MptAccountRlp,
        h_addr: &HashedAccountAddr,
        acc_storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
    ) -> TraceDecodingResult<()> {
        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = acc_storage_tries.get(h_addr).ok_or_else(|| {
                    let h_addr = *h_addr;
                    let mut e = TraceDecodingError::new(
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

fn calculate_trie_input_hashes(t_inputs: &PartialTrieState) -> MptTrieRoots {
    MptTrieRoots {
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
    extra_data: &MptExtraBlockData,
    final_tries: &PartialTrieState,
) -> [GenerationInputs; 2] {
    [
        create_dummy_gen_input(other_data, extra_data, final_tries),
        create_dummy_gen_input(other_data, extra_data, final_tries),
    ]
}

fn create_dummy_gen_input(
    other_data: &OtherBlockData,
    extra_data: &MptExtraBlockData,
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
    extra_data: &MptExtraBlockData,
    sub_tries: MptTrieInputs,
) -> GenerationInputs {
    let trie_roots_after = MptTrieRoots {
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
) -> MptTrieInputs {
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

    MptTrieInputs {
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

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    pub(crate) txn_bytes: Option<Vec<u8>>,
    pub(crate) receipt_node_bytes: Vec<u8>,
    pub(crate) gas_used: u64,
}

impl TxnMetaState {
    fn txn_bytes(&self) -> Vec<u8> {
        match self.txn_bytes.as_ref() {
            Some(v) => v.clone(),
            None => Vec::default(),
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
