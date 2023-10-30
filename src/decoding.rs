use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::{empty, once},
};

use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
    trie_subsets::create_trie_subset,
};
use ethereum_types::{Address, U256};
use plonky2_evm::{
    generation::{mpt::AccountRlp, GenerationInputs, TrieInputs},
    proof::TrieRoots,
};
use thiserror::Error;

use crate::{
    processed_block_trace::{NodesUsedByTxn, ProcessedBlockTrace, StateTrieWrites},
    types::{
        BlockLevelData, Bloom, HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles,
        OtherBlockData, TrieRootHash, TxnIdx, TxnProofGenIR, EMPTY_TRIE_HASH,
    },
    utils::update_val_if_some,
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
        let mut curr_block_tries = PartialTrieState::default();

        let mut tot_gas_used = U256::zero();
        let mut curr_bloom = Bloom::default();

        let mut txn_gen_inputs = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, txn_info)| {
                let tries = Self::create_minimal_partial_tries_needed_by_txn(
                    &curr_block_tries,
                    &txn_info.nodes_used_by_txn,
                    txn_idx,
                )?;
                let trie_roots_after = calculate_trie_input_hashes(&tries);
                let addresses = Self::get_known_addresses_if_enabled();

                let new_tot_gas_used = tot_gas_used + txn_info.meta.gas_used;
                let new_bloom = txn_info.meta.block_bloom;

                let gen_inputs = GenerationInputs {
                    txn_number_before: txn_idx.saturating_sub(1).into(),
                    gas_used_before: tot_gas_used,
                    block_bloom_before: curr_bloom,
                    gas_used_after: new_tot_gas_used,
                    block_bloom_after: new_bloom,
                    signed_txns: vec![txn_info.meta.txn_bytes],
                    tries,
                    trie_roots_after,
                    genesis_state_trie_root: other_data.genesis_state_trie_root,
                    contract_code: txn_info.contract_code_accessed,
                    block_metadata: other_data.b_data.b_meta.clone(),
                    block_hashes: other_data.b_data.b_hashes.clone(),
                    addresses,
                };

                let txn_proof_gen_ir = TxnProofGenIR {
                    txn_idx,
                    gen_inputs,
                };

                Self::apply_deltas_to_trie_state(
                    &mut curr_block_tries,
                    txn_info.nodes_used_by_txn,
                )?;

                tot_gas_used = new_tot_gas_used;
                curr_bloom = new_bloom;

                Ok(txn_proof_gen_ir)
            })
            .collect::<TraceParsingResult<Vec<_>>>()?;

        Self::pad_gen_inputs_with_dummy_inputs_if_needed(&mut txn_gen_inputs, &other_data.b_data);
        Ok(txn_gen_inputs)
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &PartialTrieState,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
    ) -> TraceParsingResult<TrieInputs> {
        let state_trie = Self::create_minimal_state_partial_trie(
            &curr_block_tries.state,
            nodes_used_by_txn.state_accesses.iter().cloned(),
        )?;

        // TODO: Replace cast once `eth_trie_utils` supports `into` for `usize...
        let transactions_trie = Self::create_trie_subset_wrapped(
            &curr_block_tries.txn,
            once((txn_idx as u32).into()),
            TrieType::Txn,
        )?;

        let receipts_trie = Self::create_trie_subset_wrapped(
            &curr_block_tries.receipt,
            once((txn_idx as u32).into()),
            TrieType::Receipt,
        )?;

        let storage_tries = Self::create_minimal_storage_partial_tries(
            &curr_block_tries.storage,
            nodes_used_by_txn.storage_accesses.iter(),
        )?;

        Ok(TrieInputs {
            state_trie,
            transactions_trie,
            receipts_trie,
            storage_tries,
        })
    }

    fn create_minimal_state_partial_trie(
        state_trie: &HashedPartialTrie,
        state_accesses: impl Iterator<Item = HashedNodeAddr>,
    ) -> TraceParsingResult<HashedPartialTrie> {
        Self::create_trie_subset_wrapped(
            state_trie,
            state_accesses.map(Nibbles::from_h256_be),
            TrieType::State,
        )
    }

    fn create_minimal_storage_partial_tries<'a>(
        storage_tries: &HashMap<HashedAccountAddr, HashedPartialTrie>,
        accesses_per_account: impl Iterator<
            Item = &'a (HashedAccountAddr, Vec<HashedStorageAddrNibbles>),
        >,
    ) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
        accesses_per_account
            .map(|(h_addr, mem_accesses)| {
                let base_storage_trie = storage_tries
                    .get(h_addr)
                    .ok_or(TraceParsingError::MissingAccountStorageTrie(*h_addr))?;
                let partial_storage_trie = Self::create_trie_subset_wrapped(
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

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: NodesUsedByTxn,
    ) -> TraceParsingResult<()> {
        for (hashed_acc_addr, storage_writes) in deltas.storage_writes {
            let storage_trie = trie_state.storage.get_mut(&hashed_acc_addr).ok_or(
                TraceParsingError::MissingAccountStorageTrie(hashed_acc_addr),
            )?;
            storage_trie.extend(storage_writes);
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.state_writes {
            let val_k = Nibbles::from_h256_be(hashed_acc_addr);
            let val_bytes = trie_state.state.get(val_k).ok_or_else(|| {
                TraceParsingError::NonExistentTrieEntry(
                    TrieType::State,
                    val_k,
                    trie_state.state.hash(),
                )
            })?;

            let mut account: AccountRlp = rlp::decode(val_bytes).map_err(|err| {
                TraceParsingError::AccountDecode(hex::encode(val_bytes), err.to_string())
            })?;
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

        Ok(())
    }

    fn pad_gen_inputs_with_dummy_inputs_if_needed(
        gen_inputs: &mut Vec<TxnProofGenIR>,
        b_data: &BlockLevelData,
    ) {
        match gen_inputs.len() {
            0 => {
                // Need to pad with two dummy txns.
                gen_inputs.extend(create_dummy_txn_pair_for_empty_block(b_data))
            }
            1 => {
                // Only need one dummy txn, but it needs info from the one real txn in the
                // block.
                gen_inputs.push(create_dummy_txn_gen_input_single_dummy_txn(
                    &gen_inputs[0].gen_inputs,
                    b_data,
                ))
            }
            _ => (),
        }
    }

    // TODO: No idea how to implement this, so I'll come back to later...
    /// If there are known addresses, return them here.
    /// Only needed for debugging purposes.
    fn get_known_addresses_if_enabled() -> Vec<Address> {
        Vec::new() // TODO
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

fn calculate_trie_input_hashes(t_inputs: &TrieInputs) -> TrieRoots {
    TrieRoots {
        state_root: t_inputs.state_trie.hash(),
        transactions_root: t_inputs.transactions_trie.hash(),
        receipts_root: t_inputs.receipts_trie.hash(),
    }
}

fn create_dummy_txn_gen_input_single_dummy_txn(
    prev_real_gen_input: &GenerationInputs,
    b_data: &BlockLevelData,
) -> TxnProofGenIR {
    let partial_sub_storage_tries: Vec<_> = prev_real_gen_input
        .tries
        .storage_tries
        .iter()
        .map(|(hashed_acc_addr, s_trie)| {
            (
                *hashed_acc_addr,
                create_fully_hashed_out_sub_partial_trie(s_trie),
            )
        })
        .collect();

    let tries = TrieInputs {
        state_trie: create_fully_hashed_out_sub_partial_trie(&prev_real_gen_input.tries.state_trie),
        transactions_trie: create_fully_hashed_out_sub_partial_trie(
            &prev_real_gen_input.tries.transactions_trie,
        ),
        receipts_trie: create_fully_hashed_out_sub_partial_trie(
            &prev_real_gen_input.tries.receipts_trie,
        ),
        storage_tries: partial_sub_storage_tries,
    };

    let gen_inputs = GenerationInputs {
        txn_number_before: 0.into(),
        gas_used_before: prev_real_gen_input.gas_used_after,
        block_bloom_before: prev_real_gen_input.block_bloom_after,
        gas_used_after: prev_real_gen_input.gas_used_after,
        block_bloom_after: prev_real_gen_input.block_bloom_after,
        signed_txns: Vec::default(),
        tries,
        trie_roots_after: prev_real_gen_input.trie_roots_after.clone(),
        genesis_state_trie_root: prev_real_gen_input.genesis_state_trie_root,
        contract_code: HashMap::default(),
        block_metadata: b_data.b_meta.clone(),
        block_hashes: b_data.b_hashes.clone(),
        addresses: Vec::default(),
    };

    gen_inputs_to_ir(gen_inputs, 1)
}

// We really want to get a trie with just a hash node here, and this is an easy
// way to do it.
fn create_fully_hashed_out_sub_partial_trie(trie: &HashedPartialTrie) -> HashedPartialTrie {
    // Impossible to actually fail with an empty iter.
    create_trie_subset(trie, empty::<Nibbles>()).unwrap()
}

fn create_dummy_txn_pair_for_empty_block(b_data: &BlockLevelData) -> [TxnProofGenIR; 2] {
    [
        create_dummy_gen_input(b_data, 0),
        create_dummy_gen_input(b_data, 1),
    ]
}

fn create_dummy_gen_input(b_data: &BlockLevelData, txn_idx: TxnIdx) -> TxnProofGenIR {
    let gen_inputs = GenerationInputs {
        txn_number_before: txn_idx.saturating_sub(1).into(),
        gas_used_before: 0.into(),
        block_bloom_before: Bloom::default(),
        gas_used_after: 0.into(),
        block_bloom_after: Bloom::default(),
        signed_txns: Vec::default(),
        tries: create_empty_trie_inputs(),
        trie_roots_after: create_trie_roots_for_empty_tries(),
        genesis_state_trie_root: TrieRootHash::default(),
        contract_code: HashMap::default(),
        block_metadata: b_data.b_meta.clone(),
        block_hashes: b_data.b_hashes.clone(),
        addresses: Vec::default(),
    };

    gen_inputs_to_ir(gen_inputs, txn_idx)
}

fn gen_inputs_to_ir(gen_inputs: GenerationInputs, txn_idx: TxnIdx) -> TxnProofGenIR {
    TxnProofGenIR {
        txn_idx,
        gen_inputs,
    }
}

fn create_empty_trie_inputs() -> TrieInputs {
    TrieInputs {
        state_trie: HashedPartialTrie::default(),
        transactions_trie: HashedPartialTrie::default(),
        receipts_trie: HashedPartialTrie::default(),
        storage_tries: Vec::default(),
    }
}

const fn create_trie_roots_for_empty_tries() -> TrieRoots {
    TrieRoots {
        state_root: EMPTY_TRIE_HASH,
        transactions_root: EMPTY_TRIE_HASH,
        receipts_root: EMPTY_TRIE_HASH,
    }
}
