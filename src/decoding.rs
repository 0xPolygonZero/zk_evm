use std::{
    collections::HashMap,
    fmt::{self, Display, Formatter},
    iter::once,
};

use eth_trie_utils::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie},
    trie_subsets::create_trie_subset,
};
use plonky2_evm::generation::{mpt::AccountRlp, GenerationInputs, TrieInputs};
use thiserror::Error;

use crate::{
    processed_block_trace::{
        BlockMetaState, NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo, StateTrieWrites,
    },
    proof_gen_types::BlockLevelData,
    types::{HashedAccountAddr, HashedNodeAddr, HashedStorageAddrNibbles, TrieRootHash, TxnIdx},
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
    fn into_generation_inputs(self, _b_data: BlockLevelData) -> Vec<GenerationInputs> {
        let _trie_state = PartialTrieState::default();
        let _b_meta_state = BlockMetaState::default();
        let txn_gen_inputs = Vec::with_capacity(self.txn_info.len());

        for (_txn_idx, _txn_info) in self.txn_info.into_iter().enumerate() {}

        txn_gen_inputs
    }

    fn create_minimal_partial_tries_needed_by_txn(
        curr_block_tries: &PartialTrieState,
        nodes_used_by_txn: NodesUsedByTxn,
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
            nodes_used_by_txn.storage_accesses.into_iter(),
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
        accesses_per_account: impl Iterator<Item = (HashedAccountAddr, Vec<HashedStorageAddrNibbles>)>,
    ) -> TraceParsingResult<Vec<(HashedAccountAddr, HashedPartialTrie)>> {
        accesses_per_account
            .map(|(h_addr, mem_accesses)| {
                let base_storage_trie = storage_tries
                    .get(&h_addr)
                    .ok_or(TraceParsingError::MissingAccountStorageTrie(h_addr))?;
                let partial_storage_trie = Self::create_trie_subset_wrapped(
                    base_storage_trie,
                    mem_accesses.into_iter(),
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
        create_trie_subset(trie, accesses)
            .map_err(|_| TraceParsingError::MissingKeysCreatingSubPartialTrie(trie_type))
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut PartialTrieState,
        deltas: ProcessedTxnInfo,
    ) -> TraceParsingResult<()> {
        for (hashed_acc_addr, storage_writes) in deltas.nodes_used_by_txn.storage_writes {
            let storage_trie = trie_state.storage.get_mut(&hashed_acc_addr).ok_or(
                TraceParsingError::MissingAccountStorageTrie(hashed_acc_addr),
            )?;
            storage_trie.extend(storage_writes);
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.nodes_used_by_txn.state_writes {
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
