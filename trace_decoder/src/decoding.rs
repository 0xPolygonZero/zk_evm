use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::once,
};

use ethereum_types::{Address, H256, U256};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::{ExtraBlockData, TrieRoots},
};
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    trie_subsets::create_trie_subset,
};
use thiserror::Error;

use crate::{
    processed_block_trace::{NodesUsedByTxn, ProcessedBlockTrace, StateTrieWrites, TxnMetaState},
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles, OtherBlockData, TrieRootHash,
        TxnIdx, TxnProofGenIR, EMPTY_ACCOUNT_BYTES_RLPED, ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, update_val_if_some},
};

pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

#[derive(Debug, Error)]
pub enum TraceParsingError {
    #[error("Failed to decode RLP bytes ({0}) as an Ethereum account due to the error: {1}")]
    AccountDecode(String, String),

    #[error("Missing account storage trie in base trie when constructing subset partial trie for txn (account: {0})")]
    MissingAccountStorageTrie(HashedAccountAddr),

    #[error("Tried accessing a non-existent key ({1}) in the {0} trie (root hash: {2:x})")]
    NonExistentTrieEntry(TrieType, Nibbles, TrieRootHash),

    // TODO: Figure out how to make this error useful/meaningful... For now this is just a
    // placeholder.
    #[error("Missing keys when creating sub-partial tries (Trie type: {0})")]
    MissingKeysCreatingSubPartialTrie(TrieType),

    #[error("No account present at {0:x} (hashed: {1:x}) to withdraw {2} Gwei from!")]
    MissingWithdrawalAccount(Address, HashedAccountAddr, U256),
}

#[derive(Debug)]
pub enum TrieType {
    State,
    Storage,
    Receipt,
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
#[derive(Debug, Default)]
struct PartialTrieState {
    state: HashedPartialTrie,
    storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
    txn: HashedPartialTrie,
    receipt: HashedPartialTrie,
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

        let mut txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, txn_info)| {
                let tries = Self::create_minimal_partial_tries_needed_by_txn(
                    &mut curr_block_tries,
                    &txn_info.nodes_used_by_txn,
                    txn_idx,
                    &other_data.b_data.b_meta.block_beneficiary,
                )?;

                // For each non-dummy txn, we increment `txn_number_after` by 1, and
                // update `gas_used_after` accordingly.
                extra_data.txn_number_after += U256::one();
                extra_data.gas_used_after += txn_info.meta.gas_used.into();

                Self::apply_deltas_to_trie_state(
                    &mut curr_block_tries,
                    txn_info.nodes_used_by_txn,
                    &txn_info.meta,
                    txn_idx,
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

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &mut PartialTrieState,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
        _coin_base_addr: &Address,
    ) -> TraceParsingResult<TrieInputs> {
        let state_trie = create_minimal_state_partial_trie(
            &curr_block_tries.state,
            nodes_used_by_txn.state_accesses.iter().cloned(),
        )?;

        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        // TODO: Replace cast once `mpt_trie` supports `into` for `usize...
        let transactions_trie =
            create_trie_subset_wrapped(&curr_block_tries.txn, once(txn_k), TrieType::Txn)?;

        let receipts_trie =
            create_trie_subset_wrapped(&curr_block_tries.receipt, once(txn_k), TrieType::Receipt)?;

        // TODO: Refactor so we can remove this vec alloc...
        let storage_access_vec = nodes_used_by_txn
            .storage_accesses
            .iter()
            .map(|(k, v)| (H256::from_slice(&k.bytes_be()), v.clone()))
            .collect::<Vec<_>>();

        let storage_tries = create_minimal_storage_partial_tries(
            &mut curr_block_tries.storage,
            &nodes_used_by_txn.state_accounts_with_no_accesses_but_storage_tries,
            storage_access_vec.iter(),
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
        deltas: NodesUsedByTxn,
        meta: &TxnMetaState,
        txn_idx: TxnIdx,
    ) -> TraceParsingResult<()> {
        for (hashed_acc_addr, storage_writes) in deltas.storage_writes {
            let storage_trie = trie_state
                .storage
                .get_mut(&H256::from_slice(&hashed_acc_addr.bytes_be()))
                .ok_or(TraceParsingError::MissingAccountStorageTrie(
                    H256::from_slice(&hashed_acc_addr.bytes_be()),
                ))?;

            for (slot, val) in storage_writes
                .into_iter()
                .map(|(k, v)| (Nibbles::from_h256_be(hash(&k.bytes_be())), v))
            {
                // If we are writing a zero, then we actually need to perform a delete.
                match val == ZERO_STORAGE_SLOT_VAL_RLPED {
                    false => storage_trie.insert(slot, val),
                    true => {
                        storage_trie.delete(slot);
                    }
                };
            }
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.state_writes {
            let val_k = Nibbles::from_h256_be(hashed_acc_addr);

            // If the account was created, then it will not exist in the trie.
            let val_bytes = trie_state
                .state
                .get(val_k)
                .unwrap_or(&EMPTY_ACCOUNT_BYTES_RLPED);

            let mut account = account_from_rlped_bytes(val_bytes)?;

            s_trie_writes.apply_writes_to_state_node(
                &mut account,
                &hashed_acc_addr,
                &trie_state.storage,
            )?;

            let updated_account_bytes = rlp::encode(&account);
            trie_state
                .state
                .insert(val_k, updated_account_bytes.to_vec());
        }

        // Remove any accounts that self-destructed.
        for hashed_addr in deltas.self_destructed_accounts {
            let k = Nibbles::from_h256_be(hashed_addr);

            trie_state
                .storage
                .remove(&hashed_addr)
                .ok_or(TraceParsingError::MissingAccountStorageTrie(hashed_addr))?;
            // TODO: Once the mechanism for resolving code hashes settles, we probably want
            // to also delete the code hash mapping here as well...

            trie_state.state.delete(k);
        }

        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
        trie_state.txn.insert(txn_k, meta.txn_bytes());

        trie_state
            .receipt
            .insert(txn_k, meta.receipt_node_bytes.as_ref());

        Ok(())
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
        extra_data: &ExtraBlockData,
        initial_tries: &PartialTrieState,
        final_tries: &PartialTrieState,
        has_withdrawals: bool,
    ) -> bool {
        match gen_inputs.len() {
            0 => {
                debug_assert!(initial_tries.state == final_tries.state);
                // We need to pad with two dummy entries.
                gen_inputs.extend(create_dummy_txn_pair_for_empty_block(
                    other_data,
                    extra_data,
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
                            create_dummy_gen_input(other_data, extra_data, initial_tries);
                        gen_inputs.insert(0, dummy_txn)
                    }
                    true => {
                        let dummy_txn = create_dummy_gen_input(other_data, extra_data, final_tries);
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
    create_trie_subset(trie, once(0_u64)).unwrap()
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
        create_minimal_state_partial_trie(&final_tries.state, account_addrs_accessed)?,
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
) -> TraceParsingResult<HashedPartialTrie> {
    create_trie_subset_wrapped(
        state_trie,
        state_accesses.into_iter().map(Nibbles::from_h256_be),
        TrieType::State,
    )
}

// TODO!!!: We really need to be appending the empty storage tries to the base
// trie somewhere else! This is a big hack!
fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &mut HashMap<HashedAccountAddr, HashedPartialTrie>,
    state_accounts_with_no_accesses_but_storage_tries: &HashMap<HashedAccountAddr, TrieRootHash>,
    accesses_per_account: impl Iterator<Item = &'a (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
    accesses_per_account
        .map(|(h_addr, mem_accesses)| {
            // TODO: Clean up...
            let base_storage_trie = match storage_tries.get(&H256(h_addr.0)) {
                Some(s_trie) => s_trie,
                None => {
                    let trie = state_accounts_with_no_accesses_but_storage_tries
                        .get(h_addr)
                        .map(|s_root| HashedPartialTrie::new(Node::Hash(*s_root)))
                        .unwrap_or_default();
                    storage_tries.insert(*h_addr, trie); // TODO: Really change this...
                    storage_tries.get(h_addr).unwrap()
                }
            };

            let partial_storage_trie = create_trie_subset_wrapped(
                base_storage_trie,
                mem_accesses.iter().cloned(),
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
