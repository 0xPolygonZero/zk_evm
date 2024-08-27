use std::{cmp::min, collections::HashMap, ops::Range};

use anyhow::{anyhow, Context as _};
use ethereum_types::{Address, BigEndianHash, H256, U256, U512};
use evm_arithmetization::{
    generation::{
        mpt::{decode_receipt, AccountRlp},
        GenerationInputs, TrieInputs,
    },
    proof::{BlockMetadata, ExtraBlockData, TrieRoots},
    testing_utils::{BEACON_ROOTS_CONTRACT_ADDRESS_HASHED, HISTORY_BUFFER_LENGTH},
};
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie as _},
    special_query::path_for_query,
    utils::{IntoTrieKey as _, TriePath},
};
use plonky2::hash::hash_types::RichField;

use crate::{
    hash,
    processed_block_trace::{
        NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo, StateWrite, TxnMetaState,
    },
    typed_mpt::{ReceiptTrie, StateTrie, StorageTrie, TransactionTrie, TrieKey},
    Field, OtherBlockData, PartialTriePreImages,
};

/// The current state of all tries as we process txn deltas. These are mutated
/// after every txn we process in the trace.
#[derive(Clone, Debug, Default)]
struct PartialTrieState {
    state: StateTrie,
    storage: HashMap<H256, StorageTrie>,
    txn: TransactionTrie,
    receipt: ReceiptTrie,
}

/// Additional information discovered during delta application.
#[derive(Debug, Default)]
struct TrieDeltaApplicationOutput {
    // During delta application, if a delete occurs, we may have to make sure additional nodes
    // that are not accessed by the txn remain unhashed.
    additional_state_trie_paths_to_not_hash: Vec<TrieKey>,
    additional_storage_trie_paths_to_not_hash: HashMap<H256, Vec<TrieKey>>,
}

pub fn into_txn_proof_gen_ir(
    ProcessedBlockTrace {
        tries: PartialTriePreImages { state, storage },
        txn_info,
        withdrawals,
    }: ProcessedBlockTrace,
    other_data: OtherBlockData,
    batch_size: usize,
) -> anyhow::Result<Vec<GenerationInputs<Field>>> {
    let mut curr_block_tries = PartialTrieState {
        state: state.clone(),
        storage: storage.iter().map(|(k, v)| (*k, v.clone())).collect(),
        ..Default::default()
    };

    let mut extra_data = ExtraBlockData {
        checkpoint_state_trie_root: other_data.checkpoint_state_trie_root,
        txn_number_before: U256::zero(),
        txn_number_after: U256::zero(),
        gas_used_before: U256::zero(),
        gas_used_after: U256::zero(),
    };

    let num_txs = txn_info
        .iter()
        .map(|tx_info| tx_info.meta.len())
        .sum::<usize>();

    let mut txn_gen_inputs = txn_info
        .into_iter()
        .enumerate()
        .map(|(txn_idx, txn_info)| {
            let txn_range =
                min(txn_idx * batch_size, num_txs)..min(txn_idx * batch_size + batch_size, num_txs);
            let is_initial_payload = txn_range.start == 0;

            process_txn_info(
                txn_range.clone(),
                is_initial_payload,
                txn_info,
                &mut curr_block_tries,
                &mut extra_data,
                &other_data,
            )
            .context(format!(
                "at transaction range {}..{}",
                txn_range.start, txn_range.end
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .context(format!(
            "at block num {} with chain id {}",
            other_data.b_data.b_meta.block_number, other_data.b_data.b_meta.block_chain_id
        ))?;

    if !withdrawals.is_empty() {
        add_withdrawals_to_txns(&mut txn_gen_inputs, &mut curr_block_tries, withdrawals)?;
    }

    Ok(txn_gen_inputs)
}

/// Cancun HF specific: At the start of a block, prior txn execution, we
/// need to update the storage of the beacon block root contract.
// See <https://eips.ethereum.org/EIPS/eip-4788>.
fn update_beacon_block_root_contract_storage(
    trie_state: &mut PartialTrieState,
    delta_out: &mut TrieDeltaApplicationOutput,
    nodes_used: &mut NodesUsedByTxn,
    block_data: &BlockMetadata,
) -> anyhow::Result<()> {
    const HISTORY_BUFFER_LENGTH_MOD: U256 = U256([HISTORY_BUFFER_LENGTH.1, 0, 0, 0]);
    const ADDRESS: H256 = H256(BEACON_ROOTS_CONTRACT_ADDRESS_HASHED);

    let timestamp_idx = block_data.block_timestamp % HISTORY_BUFFER_LENGTH_MOD;
    let timestamp = rlp::encode(&block_data.block_timestamp).to_vec();

    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH_MOD;
    let calldata = rlp::encode(&U256::from_big_endian(
        &block_data.parent_beacon_block_root.0,
    ))
    .to_vec();

    let storage_trie = trie_state
        .storage
        .get_mut(&ADDRESS)
        .context(format!("missing account storage trie {:x}", ADDRESS))?;

    let slots_nibbles = nodes_used.storage_accesses.entry(ADDRESS).or_default();

    for (ix, val) in [(timestamp_idx, timestamp), (root_idx, calldata)] {
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
        //                document this
        let slot = TrieKey::from_nibbles(Nibbles::from_h256_be(hash(
            Nibbles::from_h256_be(H256::from_uint(&ix)).bytes_be(),
        )));

        slots_nibbles.push(slot);

        // If we are writing a zero, then we actually need to perform a delete.
        match val == ZERO_STORAGE_SLOT_VAL_RLPED {
            false => {
                storage_trie.insert(slot, val.clone()).context(format!(
                    "at slot {:?} with value {}",
                    slot,
                    U512::from_big_endian(val.as_slice())
                ))?;

                delta_out
                    .additional_storage_trie_paths_to_not_hash
                    .entry(ADDRESS)
                    .or_default()
                    .push(slot);
            }
            true => {
                if let Ok(Some(remaining_slot_key)) =
                    delete_node_and_report_remaining_key_if_branch_collapsed(
                        storage_trie.as_mut_hashed_partial_trie_unchecked(),
                        &slot,
                    )
                {
                    delta_out
                        .additional_storage_trie_paths_to_not_hash
                        .entry(ADDRESS)
                        .or_default()
                        .push(remaining_slot_key);
                }
            }
        }
    }

    let addr_nibbles = TrieKey::from_hash(ADDRESS);
    delta_out
        .additional_state_trie_paths_to_not_hash
        .push(addr_nibbles);
    let mut account = trie_state
        .state
        .get_by_key(addr_nibbles)
        .context(format!("missing account storage trie {:x}", ADDRESS))?;

    account.storage_root = storage_trie.root();

    trie_state
        .state
        .insert_by_key(addr_nibbles, account)
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
        //                Add an entry API
        .expect("insert must succeed with the same key as a successful `get`");

    Ok(())
}

fn update_txn_and_receipt_tries(
    trie_state: &mut PartialTrieState,
    meta: &TxnMetaState,
    txn_idx: usize,
) -> anyhow::Result<()> {
    if let Some(bytes) = &meta.txn_bytes {
        trie_state.txn.insert(txn_idx, bytes.clone())?;
        trie_state
            .receipt
            .insert(txn_idx, meta.receipt_node_bytes.clone())?;
    } // else it's just a dummy
    Ok(())
}

/// If the account does not have a storage trie or does but is not
/// accessed by any txns, then we still need to manually create an entry for
/// them.
fn init_any_needed_empty_storage_tries<'a>(
    storage_tries: &mut HashMap<H256, StorageTrie>,
    accounts_with_storage: impl Iterator<Item = &'a H256>,
    accts_with_unaccessed_storage: &HashMap<H256, H256>,
) {
    for h_addr in accounts_with_storage {
        if !storage_tries.contains_key(h_addr) {
            let trie = accts_with_unaccessed_storage
                .get(h_addr)
                .map(|s_root| {
                    let mut it = StorageTrie::default();
                    it.insert_hash(TrieKey::default(), *s_root)
                        .expect("empty trie insert cannot fail");
                    it
                })
                .unwrap_or_default();

            storage_tries.insert(*h_addr, trie);
        };
    }
}

fn create_minimal_partial_tries_needed_by_txn(
    curr_block_tries: &PartialTrieState,
    nodes_used_by_txn: &NodesUsedByTxn,
    txn_range: Range<usize>,
    delta_application_out: TrieDeltaApplicationOutput,
) -> anyhow::Result<TrieInputs> {
    let state_trie = create_minimal_state_partial_trie(
        &curr_block_tries.state,
        nodes_used_by_txn.state_accesses.iter().cloned(),
        delta_application_out
            .additional_state_trie_paths_to_not_hash
            .into_iter(),
    )?
    .as_hashed_partial_trie()
    .clone();

    let txn_keys = txn_range.map(TrieKey::from_txn_ix);

    let transactions_trie = create_trie_subset_wrapped(
        curr_block_tries.txn.as_hashed_partial_trie(),
        txn_keys.clone(),
        TrieType::Txn,
    )?;

    let receipts_trie = create_trie_subset_wrapped(
        curr_block_tries.receipt.as_hashed_partial_trie(),
        txn_keys,
        TrieType::Receipt,
    )?;

    let storage_tries = create_minimal_storage_partial_tries(
        &curr_block_tries.storage,
        &nodes_used_by_txn.storage_accesses,
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
    meta: &[TxnMetaState],
) -> anyhow::Result<TrieDeltaApplicationOutput> {
    let mut out = TrieDeltaApplicationOutput::default();

    for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
        let storage_trie = trie_state
            .storage
            .get_mut(hashed_acc_addr)
            .context(format!(
                "missing account storage trie {:x}",
                hashed_acc_addr
            ))?;

        for (key, val) in storage_writes {
            let slot = TrieKey::from_hash(hash(key.into_nibbles().bytes_be()));
            // If we are writing a zero, then we actually need to perform a delete.
            match val == &ZERO_STORAGE_SLOT_VAL_RLPED {
                false => {
                    storage_trie.insert(slot, val.clone()).context(format!(
                        "at slot {:?} with value {}",
                        slot,
                        U512::from_big_endian(val.as_slice())
                    ))?;
                }
                true => {
                    if let Some(remaining_slot_key) =
                        delete_node_and_report_remaining_key_if_branch_collapsed(
                            storage_trie.as_mut_hashed_partial_trie_unchecked(),
                            &slot,
                        )?
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

    for (hashed_acc_addr, s_trie_writes) in &deltas.state_writes {
        let val_k = TrieKey::from_hash(*hashed_acc_addr);

        // If the account was created, then it will not exist in the trie yet.
        let is_created = !trie_state.state.contains(val_k);
        let mut account = trie_state.state.get_by_key(val_k).unwrap_or_default();

        s_trie_writes.apply_writes_to_state_node(
            &mut account,
            hashed_acc_addr,
            &trie_state.storage,
        )?;

        trie_state.state.insert_by_key(val_k, account)?;

        if is_created {
            // If the account did not exist prior this transaction, we
            // need to make sure the transaction didn't revert.

            // We will check the status of the last receipt that attempted to create the
            // account in this batch.
            let last_creation_receipt = &meta
                .iter()
                .rev()
                .find(|tx| tx.created_accounts.contains(hashed_acc_addr))
                .expect("We should have found a matching transaction")
                .receipt_node_bytes;

            let (_, _, receipt) = decode_receipt(last_creation_receipt)
                .map_err(|_| anyhow!("couldn't RLP-decode receipt node bytes"))?;

            if !receipt.status {
                // The transaction failed, hence any created account should be removed.
                if let Some(remaining_account_key) =
                    delete_node_and_report_remaining_key_if_branch_collapsed(
                        trie_state.state.as_mut_hashed_partial_trie_unchecked(),
                        &val_k,
                    )?
                {
                    out.additional_state_trie_paths_to_not_hash
                        .push(remaining_account_key);
                    trie_state.storage.remove(hashed_acc_addr);
                    continue;
                }
            }
        }
    }

    // Remove any accounts that self-destructed.
    for hashed_acc_addr in deltas.self_destructed_accounts.iter() {
        let val_k = TrieKey::from_hash(*hashed_acc_addr);

        trie_state.storage.remove(hashed_acc_addr);

        if let Some(remaining_account_key) =
            delete_node_and_report_remaining_key_if_branch_collapsed(
                trie_state.state.as_mut_hashed_partial_trie_unchecked(),
                &val_k,
            )?
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
    delete_k: &TrieKey,
) -> anyhow::Result<Option<TrieKey>> {
    let old_trace = get_trie_trace(trie, &delete_k.into_nibbles());
    trie.delete(delete_k.into_nibbles())?;
    let new_trace = get_trie_trace(trie, &delete_k.into_nibbles());
    Ok(
        node_deletion_resulted_in_a_branch_collapse(&old_trace, &new_trace)
            .map(TrieKey::from_nibbles),
    )
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

/// The withdrawals are always in the final ir payload.
fn add_withdrawals_to_txns<F: RichField>(
    txn_ir: &mut [GenerationInputs<F>],
    final_trie_state: &mut PartialTrieState,
    mut withdrawals: Vec<(Address, U256)>,
) -> anyhow::Result<()> {
    // Scale withdrawals amounts.
    for (_addr, amt) in withdrawals.iter_mut() {
        *amt = eth_to_gwei(*amt)
    }

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
        let withdrawal_addrs = withdrawals_with_hashed_addrs_iter().map(|(_, h_addr, _)| h_addr);

        let additional_paths = if last_inputs.txn_number_before == 0.into() {
            // We need to include the beacon roots contract as this payload is at the
            // start of the block execution.
            vec![TrieKey::from_hash(H256(
                BEACON_ROOTS_CONTRACT_ADDRESS_HASHED,
            ))]
        } else {
            vec![]
        };

        last_inputs.tries.state_trie = create_minimal_state_partial_trie(
            &final_trie_state.state,
            withdrawal_addrs,
            additional_paths,
        )?
        .as_hashed_partial_trie()
        .clone();
    }

    update_trie_state_from_withdrawals(
        withdrawals_with_hashed_addrs_iter(),
        &mut final_trie_state.state,
    )?;

    last_inputs.withdrawals = withdrawals;
    last_inputs.trie_roots_after.state_root = final_trie_state.state.root();

    Ok(())
}

/// Withdrawals update balances in the account trie, so we need to update
/// our local trie state.
fn update_trie_state_from_withdrawals<'a>(
    withdrawals: impl IntoIterator<Item = (Address, H256, U256)> + 'a,
    state: &mut StateTrie,
) -> anyhow::Result<()> {
    for (addr, h_addr, amt) in withdrawals {
        let mut acc_data = state.get_by_address(addr).context(format!(
            "No account present at {addr:x} (hashed: {h_addr:x}) to withdraw {amt} Gwei from!"
        ))?;

        acc_data.balance += amt;

        state
            .insert_by_address(addr, acc_data)
            // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
            //                Add an entry API
            .expect("insert must succeed with the same key as a successful `get`");
    }

    Ok(())
}

/// Processes a single transaction in the trace.
fn process_txn_info(
    txn_range: Range<usize>,
    is_initial_payload: bool,
    txn_info: ProcessedTxnInfo,
    curr_block_tries: &mut PartialTrieState,
    extra_data: &mut ExtraBlockData,
    other_data: &OtherBlockData,
) -> anyhow::Result<GenerationInputs<Field>> {
    log::trace!(
        "Generating proof IR for txn {} through {}...",
        txn_range.start,
        txn_range.end - 1
    );

    init_any_needed_empty_storage_tries(
        &mut curr_block_tries.storage,
        txn_info.nodes_used_by_txn.storage_accesses.keys(),
        &txn_info.nodes_used_by_txn.accts_with_unaccessed_storage,
    );

    // For each non-dummy txn, we increment `txn_number_after` and
    // update `gas_used_after` accordingly.
    extra_data.txn_number_after += txn_info.meta.len().into();
    extra_data.gas_used_after += txn_info.meta.iter().map(|i| i.gas_used).sum::<u64>().into();

    // Because we need to run delta application before creating the minimal
    // sub-tries (we need to detect if deletes collapsed any branches), we need to
    // do this clone every iteration.
    let tries_at_start_of_txn = curr_block_tries.clone();

    for (i, meta) in txn_info.meta.iter().enumerate() {
        update_txn_and_receipt_tries(
            curr_block_tries,
            meta,
            extra_data.txn_number_before.as_usize() + i,
        )?;
    }

    let mut delta_out = apply_deltas_to_trie_state(
        curr_block_tries,
        &txn_info.nodes_used_by_txn,
        &txn_info.meta,
    )?;

    let nodes_used_by_txn = if is_initial_payload {
        let mut nodes_used = txn_info.nodes_used_by_txn;
        update_beacon_block_root_contract_storage(
            curr_block_tries,
            &mut delta_out,
            &mut nodes_used,
            &other_data.b_data.b_meta,
        )?;

        nodes_used
    } else {
        txn_info.nodes_used_by_txn
    };

    let tries = create_minimal_partial_tries_needed_by_txn(
        &tries_at_start_of_txn,
        &nodes_used_by_txn,
        txn_range,
        delta_out,
    )?;

    let gen_inputs = GenerationInputs {
        txn_number_before: extra_data.txn_number_before,
        gas_used_before: extra_data.gas_used_before,
        gas_used_after: extra_data.gas_used_after,
        signed_txns: txn_info
            .meta
            .iter()
            .filter_map(|t| t.txn_bytes.clone())
            .collect::<Vec<_>>(),
        withdrawals: Vec::default(), /* Only ever set in a dummy txn at the end of
                                      * the block (see `[add_withdrawals_to_txns]`
                                      * for more info). */
        tries,
        trie_roots_after: TrieRoots {
            state_root: curr_block_tries.state.root(),
            transactions_root: curr_block_tries.txn.root(),
            receipts_root: curr_block_tries.receipt.root(),
        },
        checkpoint_state_trie_root: extra_data.checkpoint_state_trie_root,
        contract_code: txn_info
            .contract_code_accessed
            .into_iter()
            .map(|code| (hash(&code), code))
            .collect(),
        block_metadata: other_data.b_data.b_meta.clone(),
        block_hashes: other_data.b_data.b_hashes.clone(),
        global_exit_roots: vec![],
    };

    // After processing a transaction, we update the remaining accumulators
    // for the next transaction.
    extra_data.txn_number_before = extra_data.txn_number_after;
    extra_data.gas_used_before = extra_data.gas_used_after;

    Ok(gen_inputs)
}

impl StateWrite {
    fn apply_writes_to_state_node(
        &self,
        state_node: &mut AccountRlp,
        h_addr: &H256,
        acc_storage_tries: &HashMap<H256, StorageTrie>,
    ) -> anyhow::Result<()> {
        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = acc_storage_tries
                    .get(h_addr)
                    .context(format!("missing account storage trie {:x}", h_addr))?;

                Some(storage_trie.root())
            }
        };

        state_node.balance = self.balance.unwrap_or(state_node.balance);
        state_node.nonce = self.nonce.unwrap_or(state_node.nonce);
        state_node.storage_root = storage_root_hash_change.unwrap_or(state_node.storage_root);
        state_node.code_hash = self.code_hash.unwrap_or(state_node.code_hash);

        Ok(())
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &StateTrie,
    state_accesses: impl IntoIterator<Item = H256>,
    additional_state_trie_paths_to_not_hash: impl IntoIterator<Item = TrieKey>,
) -> anyhow::Result<StateTrie> {
    create_trie_subset_wrapped(
        state_trie.as_hashed_partial_trie(),
        state_accesses
            .into_iter()
            .map(TrieKey::from_hash)
            .chain(additional_state_trie_paths_to_not_hash),
        TrieType::State,
    )
    .map(StateTrie::from_hashed_partial_trie_unchecked)
}

// TODO!!!: We really need to be appending the empty storage tries to the base
// trie somewhere else! This is a big hack!
fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &HashMap<H256, StorageTrie>,
    accesses_per_account: impl IntoIterator<Item = (&'a H256, &'a Vec<TrieKey>)>,
    additional_storage_trie_paths_to_not_hash: &HashMap<H256, Vec<TrieKey>>,
) -> anyhow::Result<Vec<(H256, HashedPartialTrie)>> {
    accesses_per_account
        .into_iter()
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
                base_storage_trie.as_hashed_partial_trie(),
                storage_slots_to_not_hash,
                TrieType::Storage,
            )?;

            Ok((*h_addr, partial_storage_trie))
        })
        .collect()
}

fn create_trie_subset_wrapped(
    trie: &HashedPartialTrie,
    accesses: impl IntoIterator<Item = TrieKey>,
    trie_type: TrieType,
) -> anyhow::Result<HashedPartialTrie> {
    mpt_trie::trie_subsets::create_trie_subset(
        trie,
        accesses.into_iter().map(TrieKey::into_nibbles),
    )
    .context(format!("missing keys when creating {}", trie_type))
}

fn eth_to_gwei(eth: U256) -> U256 {
    // 1 ether = 10^9 gwei.
    eth * U256::from(10).pow(9.into())
}

// This is just `rlp(0)`.
const ZERO_STORAGE_SLOT_VAL_RLPED: [u8; 1] = [128];

/// Aid for error context.
/// Covers all Ethereum trie types (see <https://ethereum.github.io/yellowpaper/paper.pdf> for details).
#[derive(Debug, strum::Display)]
#[allow(missing_docs)]
enum TrieType {
    State,
    Storage,
    Receipt,
    Txn,
}
