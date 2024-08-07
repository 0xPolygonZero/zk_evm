use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::once,
};

use anyhow::Context as _;
use ethereum_types::{Address, BigEndianHash, H256, U256, U512};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::{BlockMetadata, ExtraBlockData, TrieRoots},
    testing_utils::{BEACON_ROOTS_CONTRACT_ADDRESS_HASHED, HISTORY_BUFFER_LENGTH},
};
use itertools::{Itertools, Position};
use log::trace;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, Node, PartialTrie},
    special_query::path_for_query,
    trie_ops::{TrieOpError, TrieOpResult},
    utils::{IntoTrieKey, TriePath},
};
use thiserror::Error;

use crate::{
    hash,
    processed_block_trace::{
        NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo, StateTrieWrites, TxnMetaState,
    },
    OtherBlockData, PartialTriePreImages,
};

/// Stores the result of parsing tries. Returns a [TraceParsingError] upon
/// failure.
pub type TraceParsingResult<T> = anyhow::Result<T>;

const EMPTY_ACCOUNT_BYTES_RLPED: [u8; 70] = [
    248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248,
    110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70,
    1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59,
    123, 250, 216, 4, 93, 133, 164, 112,
];

// This is just `rlp(0)`.
const ZERO_STORAGE_SLOT_VAL_RLPED: [u8; 1] = [128];

// TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
//                replace this with tracing-error
#[derive(Default, Debug)]
struct LocatedError {
    block_num: Option<U256>,
    block_chain_id: Option<U256>,
    txn_idx: Option<usize>,
    addr: Option<Address>,
    h_addr: Option<H256>,
    slot: Option<U512>,
    slot_value: Option<U512>,
}

impl fmt::Display for LocatedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn cast(it: &Option<impl Display>) -> Option<&dyn Display> {
            it.as_ref().map(|it| it as _)
        }
        let Self {
            block_num,
            block_chain_id,
            txn_idx,
            addr,
            h_addr,
            slot,
            slot_value,
        } = self;
        let h_slot = slot.map(|slot| {
            let mut buf = [0u8; 64];
            slot.to_big_endian(&mut buf);
            format!("0x{:064X}", hash(buf))
        });
        let slot_value = slot_value.map(|it| format!("0x{:064X}", it));
        let mut labels = [
            ("block num", cast(block_num)),
            ("chain id", cast(block_chain_id)),
            ("txn idx", cast(txn_idx)),
            ("address", cast(addr)),
            ("hashed address", cast(h_addr)),
            ("hashed slot", cast(slot)),
            ("slot", cast(&h_slot)),
            ("slot value", cast(&slot_value)),
        ]
        .into_iter()
        .filter_map(|(label, val)| Some((label, val?)))
        .with_position()
        .peekable();
        match labels.peek().is_some() {
            true => {
                f.write_str("at ")?;
                for (pos, (label, val)) in labels {
                    f.write_fmt(format_args!("{}: {}", label, val))?;
                    if matches!(pos, Position::First | Position::Middle) {
                        f.write_str("; ")?;
                    }
                }
            }
            // this is only reachable if someone write `LocatedError::default()`
            false => f.write_str("<error with no location information>")?,
        }
        Ok(())
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
    storage: HashMap<H256, HashedPartialTrie>,
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

pub fn into_txn_proof_gen_ir(
    ProcessedBlockTrace {
        tries: PartialTriePreImages { state, storage },
        txn_info,
        withdrawals,
    }: ProcessedBlockTrace,
    other_data: OtherBlockData,
) -> TraceParsingResult<Vec<GenerationInputs>> {
    let mut curr_block_tries = PartialTrieState {
        state: state.as_hashed_partial_trie().clone(),
        storage: storage
            .iter()
            .map(|(k, v)| (*k, v.as_hashed_partial_trie().clone()))
            .collect(),
        ..Default::default()
    };

    let mut extra_data = ExtraBlockData {
        checkpoint_state_trie_root: other_data.checkpoint_state_trie_root,
        txn_number_before: U256::zero(),
        txn_number_after: U256::zero(),
        gas_used_before: U256::zero(),
        gas_used_after: U256::zero(),
    };

    // Dummy payloads do not increment this accumulator.
    // For actual transactions, it will match their position in the block.
    let mut txn_idx = 0;

    let mut txn_gen_inputs = txn_info
        .into_iter()
        .map(|txn_info| {
            let is_initial_payload = txn_idx == 0;

            let current_idx = txn_idx;
            if !txn_info.meta.is_dummy() {
                txn_idx += 1;
            }

            process_txn_info(
                current_idx,
                is_initial_payload,
                txn_info,
                &mut curr_block_tries,
                &mut extra_data,
                &other_data,
            )
            .context(LocatedError {
                txn_idx: Some(txn_idx),
                ..Default::default()
            })
        })
        .collect::<TraceParsingResult<Vec<_>>>()
        .context(LocatedError {
            block_num: Some(other_data.b_data.b_meta.block_number),
            block_chain_id: Some(other_data.b_data.b_meta.block_chain_id),
            ..Default::default()
        })?;

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
) -> TraceParsingResult<()> {
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

    let mut slots_nibbles = vec![];

    for (slot, val) in [(timestamp_idx, timestamp), (root_idx, calldata)]
        .iter()
        .map(|(k, v)| {
            (
                Nibbles::from_h256_be(hash(Nibbles::from_h256_be(H256::from_uint(k)).bytes_be())),
                v,
            )
        })
    {
        slots_nibbles.push(slot);

        // If we are writing a zero, then we actually need to perform a delete.
        match val == &ZERO_STORAGE_SLOT_VAL_RLPED {
            false => {
                storage_trie
                    .insert(slot, val.clone())
                    .context(LocatedError {
                        slot: Some(U512::from_big_endian(slot.bytes_be().as_slice())),
                        slot_value: Some(U512::from_big_endian(val.as_slice())),
                        ..Default::default()
                    })?;

                delta_out
                    .additional_storage_trie_paths_to_not_hash
                    .entry(ADDRESS)
                    .or_default()
                    .push(slot);
            }
            true => {
                if let Ok(Some(remaining_slot_key)) =
                    delete_node_and_report_remaining_key_if_branch_collapsed(storage_trie, &slot)
                {
                    delta_out
                        .additional_storage_trie_paths_to_not_hash
                        .entry(ADDRESS)
                        .or_default()
                        .push(remaining_slot_key);
                }
            }
        };
    }

    nodes_used.storage_accesses.push((ADDRESS, slots_nibbles));

    let addr_nibbles = Nibbles::from_h256_be(ADDRESS);
    delta_out
        .additional_state_trie_paths_to_not_hash
        .push(addr_nibbles);
    let addr_bytes = trie_state
        .state
        .get(addr_nibbles)
        .context(format!("missing account storage trie {:x}", ADDRESS))?;
    let mut account = account_from_rlped_bytes(addr_bytes)?;

    account.storage_root = storage_trie.hash();

    let updated_account_bytes = rlp::encode(&account);
    trie_state
        .state
        .insert(addr_nibbles, updated_account_bytes.to_vec())
        .context(LocatedError {
            slot: Some(U512::from_big_endian(addr_nibbles.bytes_be().as_slice())),
            ..Default::default()
        })?;

    Ok(())
}

fn update_txn_and_receipt_tries(
    trie_state: &mut PartialTrieState,
    meta: &TxnMetaState,
    txn_idx: usize,
) -> TrieOpResult<()> {
    if meta.is_dummy() {
        // This is a dummy payload, that does not mutate these tries.
        return Ok(());
    }

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
    storage_tries: &mut HashMap<H256, HashedPartialTrie>,
    accounts_with_storage: impl Iterator<Item = &'a H256>,
    state_accounts_with_no_accesses_but_storage_tries: &'a HashMap<H256, H256>,
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
    txn_idx: usize,
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

    let transactions_trie =
        create_trie_subset_wrapped(&curr_block_tries.txn, once(txn_k), TrieType::Txn)?;

    let receipts_trie =
        create_trie_subset_wrapped(&curr_block_tries.receipt, once(txn_k), TrieType::Receipt)?;

    let storage_tries = create_minimal_storage_partial_tries(
        &curr_block_tries.storage,
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
) -> TraceParsingResult<TrieDeltaApplicationOutput> {
    let mut out = TrieDeltaApplicationOutput::default();

    for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
        let storage_trie = trie_state
            .storage
            .get_mut(hashed_acc_addr)
            .context(format!(
                "missing account storage trie {:x}",
                hashed_acc_addr
            ))
            .context(LocatedError {
                h_addr: Some(*hashed_acc_addr),
                ..Default::default()
            })?;

        for (slot, val) in storage_writes
            .iter()
            .map(|(k, v)| (Nibbles::from_h256_be(hash(k.bytes_be())), v))
        {
            // If we are writing a zero, then we actually need to perform a delete.
            match val == &ZERO_STORAGE_SLOT_VAL_RLPED {
                false => storage_trie
                    .insert(slot, val.clone())
                    .context(LocatedError {
                        slot: Some(U512::from_big_endian(slot.bytes_be().as_slice())),
                        slot_value: Some(U512::from_big_endian(val.as_slice())),
                        ..Default::default()
                    })?,
                true => {
                    if let Some(remaining_slot_key) =
                        delete_node_and_report_remaining_key_if_branch_collapsed(
                            storage_trie,
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
            .insert(val_k, updated_account_bytes.to_vec())?;
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
    let old_trace = get_trie_trace(trie, delete_k);
    trie.delete(*delete_k)?;
    let new_trace = get_trie_trace(trie, delete_k);

    Ok(node_deletion_resulted_in_a_branch_collapse(
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

/// The withdrawals are always in the final ir payload.
fn add_withdrawals_to_txns(
    txn_ir: &mut [GenerationInputs],
    final_trie_state: &mut PartialTrieState,
    mut withdrawals: Vec<(Address, U256)>,
) -> TraceParsingResult<()> {
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

    if last_inputs.signed_txn.is_none() {
        // This is a dummy payload, hence it does not contain yet
        // state accesses to the withdrawal addresses.
        let withdrawal_addrs = withdrawals_with_hashed_addrs_iter().map(|(_, h_addr, _)| h_addr);

        let additional_paths = if last_inputs.txn_number_before == 0.into() {
            // We need to include the beacon roots contract as this payload is at the
            // start of the block execution.
            vec![Nibbles::from_h256_be(H256(
                BEACON_ROOTS_CONTRACT_ADDRESS_HASHED,
            ))]
        } else {
            vec![]
        };

        last_inputs.tries.state_trie = create_minimal_state_partial_trie(
            &final_trie_state.state,
            withdrawal_addrs,
            additional_paths.into_iter(),
        )?;
    }

    update_trie_state_from_withdrawals(
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
    withdrawals: impl IntoIterator<Item = (Address, H256, U256)> + 'a,
    state: &mut HashedPartialTrie,
) -> TraceParsingResult<()> {
    for (addr, h_addr, amt) in withdrawals {
        let h_addr_nibs = Nibbles::from_h256_be(h_addr);

        let acc_bytes = state.get(h_addr_nibs).context(format!(
            "No account present at {addr:x} (hashed: {h_addr:x}) to withdraw {amt} Gwei from!"
        ))?;
        let mut acc_data = account_from_rlped_bytes(acc_bytes)?;

        acc_data.balance += amt;

        state.insert(h_addr_nibs, rlp::encode(&acc_data).to_vec())?;
    }

    Ok(())
}

/// Processes a single transaction in the trace.
fn process_txn_info(
    txn_idx: usize,
    is_initial_payload: bool,
    txn_info: ProcessedTxnInfo,
    curr_block_tries: &mut PartialTrieState,
    extra_data: &mut ExtraBlockData,
    other_data: &OtherBlockData,
) -> TraceParsingResult<GenerationInputs> {
    trace!("Generating proof IR for txn {}...", txn_idx);

    init_any_needed_empty_storage_tries(
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
    extra_data.txn_number_after += U256::from(!txn_info.meta.is_dummy() as u8);
    extra_data.gas_used_after += txn_info.meta.gas_used.into();

    // Because we need to run delta application before creating the minimal
    // sub-tries (we need to detect if deletes collapsed any branches), we need to
    // do this clone every iteration.
    let tries_at_start_of_txn = curr_block_tries.clone();

    update_txn_and_receipt_tries(curr_block_tries, &txn_info.meta, txn_idx)?;

    let mut delta_out = apply_deltas_to_trie_state(curr_block_tries, &txn_info.nodes_used_by_txn)?;

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
        global_exit_roots: vec![],
    };

    // After processing a transaction, we update the remaining accumulators
    // for the next transaction.
    extra_data.txn_number_before = extra_data.txn_number_after;
    extra_data.gas_used_before = extra_data.gas_used_after;

    Ok(gen_inputs)
}

impl StateTrieWrites {
    fn apply_writes_to_state_node(
        &self,
        state_node: &mut AccountRlp,
        h_addr: &H256,
        acc_storage_tries: &HashMap<H256, HashedPartialTrie>,
    ) -> TraceParsingResult<()> {
        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = acc_storage_tries
                    .get(h_addr)
                    .context(format!("missing account storage trie {:x}", h_addr))?;

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

fn create_minimal_state_partial_trie(
    state_trie: &HashedPartialTrie,
    state_accesses: impl Iterator<Item = H256>,
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
    storage_tries: &HashMap<H256, HashedPartialTrie>,
    accesses_per_account: impl Iterator<Item = &'a (H256, Vec<Nibbles>)>,
    additional_storage_trie_paths_to_not_hash: &HashMap<H256, Vec<Nibbles>>,
) -> TraceParsingResult<Vec<(H256, HashedPartialTrie)>> {
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
    mpt_trie::trie_subsets::create_trie_subset(trie, accesses)
        .context(format!("missing keys when creating {}", trie_type))
}

fn account_from_rlped_bytes(bytes: &[u8]) -> TraceParsingResult<AccountRlp> {
    Ok(rlp::decode(bytes)?)
}

impl TxnMetaState {
    /// Outputs a boolean indicating whether this `TxnMetaState`
    /// represents a dummy payload or an actual transaction.
    const fn is_dummy(&self) -> bool {
        self.txn_bytes.is_none()
    }

    fn txn_bytes(&self) -> Vec<u8> {
        match self.txn_bytes.as_ref() {
            Some(v) => v.clone(),
            None => Vec::default(),
        }
    }
}

fn update_val_if_some<T>(target: &mut T, opt: Option<T>) {
    if let Some(new_val) = opt {
        *target = new_val;
    }
}

fn optional_field<T: std::fmt::Debug>(label: &str, value: Option<T>) -> String {
    value.map_or(String::new(), |v| format!("{}: {:?}\n", label, v))
}

fn optional_field_hex<T: std::fmt::UpperHex>(label: &str, value: Option<T>) -> String {
    value.map_or(String::new(), |v| format!("{}: 0x{:064X}\n", label, v))
}

fn eth_to_gwei(eth: U256) -> U256 {
    // 1 ether = 10^9 gwei.
    eth * U256::from(10).pow(9.into())
}
