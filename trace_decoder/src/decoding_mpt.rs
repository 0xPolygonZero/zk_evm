use std::{
    collections::HashMap,
    iter::{self, empty, once},
};

use ethereum_types::{Address, U256, U512};
use evm_arithmetization_mpt::{
    generation::{mpt::AccountRlp, TrieInputs},
    proof::{BlockHashes, BlockMetadata},
    GenerationInputs,
};
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
use rlp::Decodable;

use crate::{
    aliased_crate_types::{ExtraBlockData, TrieRoots},
    compact::compact_mpt_processing::MptPartialTriePreImages,
    decoding::{
        self, create_trie_subset_wrapped, GenIr, ProcessedBlockTraceDecode, StateTrie,
        StorageTries, TraceDecodingError, TraceDecodingErrorReason, TraceDecodingResult, Trie,
        TrieState, TrieType,
    },
    processed_block_trace::{
        NodesUsedByTxn, ProcessedSectionInfo, ProcessedSectionTxnInfo, ProcessingMeta,
        StateTrieWrites,
    },
    processed_block_trace_mpt::{
        MptBlockTraceProcessing, MptProcessedBlockTrace, ProcedBlockTraceMptSpec,
    },
    protocol_processing::TraceProtocolDecodingResult,
    trace_protocol::BlockTrace,
    types::{
        CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr, HashedStorageAddr,
        HashedStorageAddrNibbles, OtherBlockData, TrieRootHash, TxnIdx, EMPTY_ACCOUNT_BYTES_RLPED,
        ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, nibbles_to_h256, update_val_if_some},
};

type MptTrieState = TrieState<MptBlockTraceDecoding>;

#[derive(Clone, Debug)]
struct MptStorageTries(HashMap<HashedAccountAddr, HashedPartialTrie>);

impl From<HashMap<HashedAccountAddr, HashedPartialTrie>> for MptStorageTries {
    fn from(v: HashMap<HashedAccountAddr, HashedPartialTrie>) -> Self {
        Self(v)
    }
}

impl FromIterator<(HashedAccountAddr, HashedPartialTrie)> for MptStorageTries {
    fn from_iter<T: IntoIterator<Item = (HashedAccountAddr, HashedPartialTrie)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl StorageTries for MptStorageTries {
    type StorageTrie = MptTrie;

    fn get_trie(&self, h_addr: &HashedAccountAddr) -> Option<&Self::StorageTrie> {
        todo!()
    }

    fn get_mut_trie(&mut self, h_addr: &HashedAccountAddr) -> Option<&mut Self::StorageTrie> {
        todo!()
    }

    fn get_trie_and_create_mut(&mut self, h_addr: &HashedAccountAddr) -> &mut Self::StorageTrie {
        todo!()
    }

    fn remove_trie(&mut self, addr: &HashedAccountAddr) -> Option<Self::StorageTrie> {
        todo!()
    }
}

pub(crate) struct MptBlockTraceDecoding;

impl ProcessedBlockTraceDecode for MptBlockTraceDecoding {
    type Spec = ProcedBlockTraceMptSpec;
    type Ir = GenerationInputs;
    type TrieInputs = TrieInputs;
    type StateTrie = MptTrie;
    type StorageTries = MptStorageTries;
    type ReceiptTrie = MptTrie;
    type TxnTrie = MptTrie;

    fn get_trie_pre_image(spec: &Self::Spec) -> TrieState<Self> {
        todo!()
    }

    fn create_trie_subsets(
        tries: &TrieState<Self>,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
    ) -> TraceDecodingResult<TrieState<Self>> {
        todo!()
    }

    fn create_dummy_ir(
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_tries: &TrieState<Self>,
        account_addrs_accessed: impl Iterator<Item = HashedAccountAddr>,
    ) -> Self::Ir {
        let sub_tries = create_dummy_proof_tries_mpt(
            final_tries,
            create_minimal_state_partial_trie(
                &final_tries.state,
                account_addrs_accessed,
                iter::empty(),
            )
            .expect(
                "Managed to error when creating a fully hashed out trie! (should not be possible)",
            ),
        );

        let trie_roots_after = TrieRoots {
            state_root: sub_tries.state.trie_hash(),
            transactions_root: sub_tries.txn.trie_hash(),
            receipts_root: sub_tries.receipt.trie_hash(),
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

        let sub_trie_inputs = Self::create_trie_inputs(sub_tries);

        Self::create_ir(
            extra_data.txn_number_before,
            extra_data.gas_used_before,
            extra_data.gas_used_after,
            None,
            vec![], // this is set after creating dummy payloads,
            sub_trie_inputs,
            trie_roots_after,
            extra_data.checkpoint_state_trie_root,
            HashMap::default(),
            other_data.b_data.b_meta.clone(),
            other_data.b_data.b_hashes.clone(),
        )
    }

    fn create_trie_inputs(tries: TrieState<Self>) -> Self::TrieInputs {
        let storage_tries = Vec::from_iter(tries.storage.0.into_iter());

        TrieInputs {
            state_trie: tries.state.trie,
            transactions_trie: tries.txn.trie,
            receipts_trie: tries.receipt.trie,
            storage_tries,
        }
    }

    fn create_ir(
        txn_number_before: U256,
        gas_used_before: U256,
        gas_used_after: U256,
        signed_txn: Option<Vec<u8>>,
        withdrawals: Vec<(Address, U256)>,
        tries: Self::TrieInputs,
        trie_roots_after: crate::aliased_crate_types::TrieRoots,
        checkpoint_state_trie_root: TrieRootHash,
        contract_code: HashMap<H256, Vec<u8>>,
        block_metadata: BlockMetadata,
        block_hashes: BlockHashes,
    ) -> Self::Ir {
        Self::Ir {
            txn_number_before,
            gas_used_before,
            gas_used_after,
            signed_txn,
            withdrawals,
            tries,
            trie_roots_after,
            checkpoint_state_trie_root,
            contract_code,
            block_metadata,
            block_hashes,
        }
    }
}

#[derive(Clone, Debug)]
struct MptTrie {
    trie: HashedPartialTrie,
    traced_delete_info: TrieDeltaApplicationOutput,
}

impl From<HashedPartialTrie> for MptTrie {
    fn from(v: HashedPartialTrie) -> Self {
        Self {
            trie: v,
            traced_delete_info: Default::default(),
        }
    }
}

impl Trie for MptTrie {
    fn trie_contains(&self, k: Nibbles) -> TraceDecodingResult<bool> {
        // TODO: Replace with `trie.contains` once we add that function to the
        // `mpt_trie`...
        Ok(self.trie.get(k).is_some())
    }

    fn trie_get(&self, k: Nibbles) -> Option<&[u8]> {
        self.trie.get(k)
    }

    fn trie_insert<V: Into<decoding::NodeInsertType>>(
        &mut self,
        k: Nibbles,
        v: V,
    ) -> TraceDecodingResult<()> {
        self.trie
            .insert(k, v.into())
            .map_err(|err| TraceDecodingError::new(TraceDecodingErrorReason::TrieOpError(err)))
    }

    /// If a branch collapse occurred after a delete, then we must ensure that
    /// the other single child that remains also is not hashed when passed into
    /// plonky2. Returns the key to the remaining child if a collapse occurred.
    fn trie_delete(&mut self, k: Nibbles) -> TraceDecodingResult<()> {
        let old_trace = Self::get_trie_trace(&self.trie, &k);
        self.trie.delete(k)?;
        let new_trace = Self::get_trie_trace(&self.trie, &k);

        if let Some(branch_collapse_key) =
            Self::node_deletion_resulted_in_a_branch_collapse(&old_trace, &new_trace)
        {
            self.traced_delete_info
                .additional_storage_trie_paths_to_not_hash
                .entry(nibbles_to_h256(&k))
                .or_default()
                .push(branch_collapse_key);
        }

        Ok(())
    }

    fn trie_create_trie_subset<K>(
        &self,
        ks: impl Iterator<Item = K>,
        trie_type: TrieType,
    ) -> TraceDecodingResult<Self>
    where
        K: Into<Nibbles>,
        Self: Sized,
    {
        create_trie_subset(&self.trie, ks)
            .map_err(|err| {
                let key = match err {
                    SubsetTrieError::UnexpectedKey(key, _) => key,
                };

                TraceDecodingError::new(
                    TraceDecodingErrorReason::MissingKeysCreatingSubPartialTrie(key, trie_type),
                )
            })
            .map(|trie| trie.into())
    }

    fn trie_hash(&self) -> TrieRootHash {
        self.trie.hash()
    }
}

impl StateTrie for MptTrie {
    fn get_account(&self, addr: Nibbles) -> TraceDecodingResult<Option<AccountRlp>> {
        let acc_bytes = self.trie_get(addr);

        let res = match acc_bytes {
            Some(bytes) => Some(rlp::decode(bytes).map_err(|err| {
                TraceDecodingError::new(TraceDecodingErrorReason::AccountDecode(
                    hex::encode(bytes),
                    err.to_string(),
                ))
            })?),
            None => None,
        };

        Ok(res)
    }

    fn set_account(&mut self, addr: Nibbles, acc: &AccountRlp) {
        self.trie.insert(addr, rlp::encode(acc).to_vec());
    }
}

impl MptTrie {
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

impl Trie for HashedPartialTrie {
    fn trie_contains(&self, k: Nibbles) -> TraceDecodingResult<bool> {
        todo!()
    }

    fn trie_get(&self, k: Nibbles) -> Option<&[u8]> {
        todo!()
    }

    fn trie_insert<V: Into<decoding::NodeInsertType>>(
        &mut self,
        k: Nibbles,
        v: V,
    ) -> TraceDecodingResult<()> {
        todo!()
    }

    fn trie_delete(&mut self, k: Nibbles) -> TraceDecodingResult<()> {
        todo!()
    }

    fn trie_create_trie_subset<K>(
        &self,
        ks: impl Iterator<Item = K>,
        trie_type: TrieType,
    ) -> TraceDecodingResult<Self>
    where
        K: Into<Nibbles>,
        Self: Sized,
    {
        todo!()
    }

    fn trie_hash(&self) -> TrieRootHash {
        todo!()
    }
}

impl GenIr for GenerationInputs {
    type TrieRoots = TrieRoots;

    type StateTrie = MptTrie;

    fn get_signed_txn(&self) -> Option<&[u8]> {
        todo!()
    }

    fn get_withdrawals_mut(&mut self) -> &mut Vec<(Address, U256)> {
        todo!()
    }

    fn get_state_trie_mut(&mut self) -> &mut Self::StateTrie {
        todo!()
    }

    fn get_trie_roots_mut(&mut self) -> &mut TrieRoots {
        todo!()
    }
}

impl MptProcessedBlockTrace {
    pub(crate) fn into_proof_gen_mpt_ir(
        self,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>> {
        todo!()
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &MptTrie,
    state_accesses: impl Iterator<Item = HashedNodeAddr>,
    additional_state_trie_paths_to_not_hash: impl Iterator<Item = Nibbles>,
) -> TraceDecodingResult<MptTrie> {
    create_trie_subset_wrapped(
        state_trie,
        state_accesses
            .into_iter()
            .map(Nibbles::from_h256_be)
            .chain(additional_state_trie_paths_to_not_hash),
        TrieType::State,
    )
}

fn account_from_rlped_bytes(bytes: &[u8]) -> TraceDecodingResult<AccountRlp> {
    rlp::decode(bytes).map_err(|err| {
        TraceDecodingError::new(TraceDecodingErrorReason::AccountDecode(
            hex::encode(bytes),
            err.to_string(),
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

        let res = processed_block_trace
            .into_proof_gen_ir(other_data)
            .map_err(|err| Box::new(err))?;

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
        self.into_processed_block_trace::<_, MptBlockTraceProcessing, MptBlockTraceDecoding>(
            p_meta,
            withdrawals,
        )
    }
}

fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &MptStorageTries,
    accesses_per_account: impl Iterator<
        Item = (
            HashedAccountAddr,
            impl Iterator<Item = HashedStorageAddrNibbles>,
        ),
    >,
) -> TraceDecodingResult<MptStorageTries> {
    accesses_per_account
        .map(|(h_addr, mem_accesses)| {
            // Guaranteed to exist due to calling `init_any_needed_empty_storage_tries`
            // earlier on.
            let base_storage_trie = storage_tries
                .0
                .get(&h_addr)
                .expect("Base storage trie missing! This should not be possible!");

            let partial_storage_trie =
                create_trie_subset_wrapped(base_storage_trie, mem_accesses, TrieType::Storage)?;

            Ok((h_addr, partial_storage_trie))
        })
        .collect::<TraceDecodingResult<_>>()
}

fn create_minimal_partial_tries_needed_by_txn(
    curr_block_tries: &MptTrieState,
    nodes_used_by_txn: &NodesUsedByTxn,
    txn_idx: TxnIdx,
    delta_application_out: TrieDeltaApplicationOutput,
) -> TraceDecodingResult<MptTrieState> {
    let state = create_minimal_state_partial_trie(
        &curr_block_tries.state,
        nodes_used_by_txn.state_accesses.iter().cloned(),
        delta_application_out
            .additional_state_trie_paths_to_not_hash
            .into_iter(),
    )?;

    let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();
    // TODO: Replace cast once `mpt_trie` supports `into` for `usize...
    let txn = create_trie_subset_wrapped(&curr_block_tries.txn, once(txn_k), TrieType::Txn)?;

    let receipt =
        create_trie_subset_wrapped(&curr_block_tries.receipt, once(txn_k), TrieType::Receipt)?;

    let storage_accesses = nodes_used_by_txn.state_accesses.iter().map(|h_addr| {
        let x = delta_application_out
            .additional_storage_trie_paths_to_not_hash
            .get(h_addr)
            .into_iter()
            .flat_map(|slots| slots.iter().cloned());

        (*h_addr, x)
    });

    let storage =
        create_minimal_storage_partial_tries(&curr_block_tries.storage, storage_accesses)?;

    Ok(MptTrieState {
        state,
        storage,
        receipt,
        txn,
    })
}

// We really want to get a trie with just a hash node here, and this is an easy
// way to do it.
pub(crate) fn create_fully_hashed_out_sub_partial_trie<U: Trie>(
    trie: &U,
    trie_type: TrieType,
) -> U {
    // Impossible to actually fail with an empty iter.
    trie.trie_create_trie_subset(empty::<Nibbles>(), trie_type)
        .unwrap()
}

fn create_dummy_proof_tries_mpt(
    final_tries_at_end_of_block: &MptTrieState,
    state_trie: MptTrie,
) -> MptTrieState {
    let partial_sub_storage_tries = final_tries_at_end_of_block
        .storage
        .0
        .iter()
        .map(|(hashed_acc_addr, s_trie)| {
            (
                *hashed_acc_addr,
                create_fully_hashed_out_sub_partial_trie(s_trie, TrieType::Storage),
            )
        })
        .collect();

    MptTrieState {
        state: state_trie,
        storage: partial_sub_storage_tries,
        receipt: create_fully_hashed_out_sub_partial_trie(
            &final_tries_at_end_of_block.receipt,
            TrieType::Receipt,
        ),
        txn: create_fully_hashed_out_sub_partial_trie(
            &final_tries_at_end_of_block.txn,
            TrieType::Txn,
        ),
    }
}

/// Additional information discovered during delta application.
#[derive(Clone, Debug, Default)]
struct TrieDeltaApplicationOutput {
    // During delta application, if a delete occurs, we may have to make sure additional nodes
    // that are not accessed by the txn remain unhashed.
    additional_state_trie_paths_to_not_hash: Vec<Nibbles>,
    additional_storage_trie_paths_to_not_hash: HashMap<H256, Vec<Nibbles>>,
}
