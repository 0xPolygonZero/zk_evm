use std::{
    collections::HashMap, iter::{empty, once}, marker::PhantomData, ops::Deref
};

use ethereum_types::{Address, U256};
use evm_arithmetization_mpt::{
    generation::{mpt::AccountRlp, TrieInputs},
    proof::{BlockHashes, BlockMetadata},
    GenerationInputs,
};
use keccak_hash::H256;
use mpt_trie_normal::{
    nibbles::{self, Nibbles},
    partial_trie::{HashedPartialTrie, PartialTrie},
    special_query::path_for_query,
    trie_subsets::{create_trie_subset, SubsetTrieError},
    utils::{IntoTrieKey, TriePath},
};

use crate::{
    aliased_crate_types::{ExtraBlockData, TrieRoots}, compact::compact_processing_common::CompactParsingError, decoding::{
        self, calculate_trie_root_hashes, create_trie_subset_wrapped, GenIr, NodeInsertType, ProcessedBlockTraceDecode, StateTrie, StorageTrie, StorageTries, TraceDecodingError, TraceDecodingErrorReason, TraceDecodingResult, Trie, TrieState, TrieType, WrappedHashedPartialTrie, WrappedNibbles
    }, processed_block_trace::{NodesUsedByTxn, ProcessingMeta}, processed_block_trace_mpt::{
        MptBlockTraceProcessing, MptProcessedBlockTrace,
    }, trace_protocol::BlockTrace, types::{
        AccountInfo, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr,
        HashedStorageAddrNibbles, OtherBlockData, StorageAddr, TrieRootHash, TxnIdx, EMPTY_TRIE_HASH,
    }, utils::{hash, hash_addr_to_nibbles, hash_slot_to_nibbles, nibbles_to_h256, nibbles_to_u256, u256_to_bytes}
};

type MptTrieState = TrieState<MptBlockTraceDecoding>;

type MptStateTrie = MptTrie<Address>;
type MptStorageTrie = MptTrie<StorageAddr>;

impl BlockTrace {
    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn into_proof_gen_mpt_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_mpt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MptStorageTries(HashMap<HashedAccountAddr, MptStorageTrie>);

impl From<HashMap<HashedAccountAddr, MptStorageTrie>> for MptStorageTries {
    fn from(v: HashMap<HashedAccountAddr, MptStorageTrie>) -> Self {
        Self(v)
    }
}

impl FromIterator<(HashedAccountAddr, MptStorageTrie)> for MptStorageTries {
    fn from_iter<T: IntoIterator<Item = (HashedAccountAddr, MptStorageTrie)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl StorageTries for MptStorageTries {
    type StorageTrie = MptTrie<StorageAddr>;

    fn get_trie(&self, addr: Address) -> Option<&Self::StorageTrie> {
        self.0.get(&hash(&addr.as_bytes()))
    }

    fn get_mut_trie(&mut self, addr: Address) -> Option<&mut Self::StorageTrie> {
        self.0.get_mut(&hash(&addr.as_bytes()))
    }

    fn get_trie_or_create_mut(&mut self, addr: Address) -> &mut Self::StorageTrie {
        self.0.entry(hash(addr.as_bytes())).or_default()
    }

    fn remove_trie(&mut self, addr: Address) -> bool {
        self.0.remove(&hash(addr.as_bytes())).is_some()
    }
}

pub(crate) struct MptBlockTraceDecoding;

impl ProcessedBlockTraceDecode for MptBlockTraceDecoding {
    type Spec = ProcedBlockTraceMptSpec;
    type Ir = MptGenInputs;
    type TrieInputs = TrieInputs;
    type StateTrie = MptTrie<Address>;
    type StorageTries = MptStorageTries;
    type ReceiptTrie = WrappedHashedPartialTrie<TxnIdx>;
    type TxnTrie = WrappedHashedPartialTrie<TxnIdx>;

    fn get_trie_pre_image(spec: &Self::Spec) -> MptTrieState {
        MptTrieState {
            state: spec.tries.state.clone().into(),
            storage: MptStorageTries::from_iter(
                spec.tries
                    .storage
                    .iter()
                    .map(|(k, t)| (*k, t.clone().into())),
            ),
            receipt: HashedPartialTrie::default().into(),
            txn: HashedPartialTrie::default().into(),
        }
    }

    /// If the account does not have a storage trie or does but is not
    /// accessed by any txns, then we still need to manually create an entry for
    /// them.
    fn init_any_needed_empty_storage_tries<'a>(
        storage_tries: &mut Self::StorageTries,
        accounts_with_storage: impl Iterator<Item = &'a Address>,
        state_accounts_with_no_accesses_but_storage_tries: &'a HashMap<Address, TrieRootHash>,
    ) {
        for addr in accounts_with_storage {
            if storage_tries.get_trie(*addr).is_none() {
                // If the account does not have accesses but has storage that is not accessed,
                // then we still need to create a hashed out storage trie for the account.
                let trie: &mut <<Self as ProcessedBlockTraceDecode>::StorageTries as StorageTries>::StorageTrie = storage_tries.get_trie_or_create_mut(*addr);
                trie.hash_out_trie();
            };
        }
    }

    fn create_trie_subsets(
        tries: &TrieState<Self>,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
    ) -> TraceDecodingResult<TrieState<Self>> {
        let state = create_minimal_state_partial_trie(
            &tries.state,
            nodes_used_by_txn.state_accesses.iter().cloned(),
        )?;

        let txn_key = Nibbles::from(txn_idx as u32);

        // TODO: Replace cast once `mpt_trie` supports `into` for `usize...
        let txn = create_trie_subset_wrapped(&tries.txn, once(txn_key), TrieType::Txn)?;
        let receipt = create_trie_subset_wrapped(&tries.receipt, once(txn_key), TrieType::Receipt)?;

        let storage = create_minimal_storage_partial_tries(
            &tries.storage,
            nodes_used_by_txn
                .storage_accesses
                .iter()
                .map(|(k, v)| (hash(k.as_bytes()), v.iter().cloned())),
        )?;

        Ok(MptTrieState {
            state,
            storage,
            receipt,
            txn,
        })
    }

    fn create_dummy_ir(
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_tries: &TrieState<Self>,
        account_addrs_accessed: impl Iterator<Item = Address>,
    ) -> Self::Ir {
        let sub_tries = create_dummy_proof_tries_mpt(
            final_tries,
            create_minimal_state_partial_trie(&final_tries.state, account_addrs_accessed).expect(
                "Managed to error when creating a fully hashed out trie! (should not be possible)",
            ),
        );

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
            extra_data.checkpoint_state_trie_root,
            HashMap::default(),
            other_data.b_data.b_meta.clone(),
            other_data.b_data.b_hashes.clone(),
        )
    }

    fn create_trie_inputs(tries: TrieState<Self>) -> Self::TrieInputs {
        let storage_tries = Vec::from_iter(tries.storage.0.into_iter().map(|(k, t)| (k, t.trie)));

        TrieInputs {
            state_trie: tries.state.trie,
            transactions_trie: tries.txn.inner,
            receipts_trie: tries.receipt.inner,
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
        checkpoint_state_trie_root: TrieRootHash,
        contract_code: HashMap<H256, Vec<u8>>,
        block_metadata: BlockMetadata,
        block_hashes: BlockHashes,
    ) -> Self::Ir {
        let trie_roots_after = TrieRoots {
            state_root: tries.state_trie.hash(),
            transactions_root: tries.transactions_trie.hash(),
            receipts_root: tries.receipts_trie.hash(),
        };

        MptGenInputs(GenerationInputs {
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
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MptTrie<K> {
    trie: HashedPartialTrie,
    additional_trie_paths_to_not_hash: Vec<Nibbles>,

    _key_type: PhantomData<K>,
}

impl<K> Deref for MptTrie<K> {
    type Target = HashedPartialTrie;

    fn deref(&self) -> &Self::Target {
        &self.trie
    }
}

impl<K> From<HashedPartialTrie> for MptTrie<K> {
    fn from(v: HashedPartialTrie) -> Self {
        Self::new(v)
    }
}

impl<K> From<WrappedHashedPartialTrie<K>> for MptTrie<K> {
    fn from(v: WrappedHashedPartialTrie<K>) -> Self {
        Self::new(v.inner)
    }
}

impl<T> MptTrie<T> {
    fn new(trie: HashedPartialTrie) -> Self {
        Self {
            trie,
            additional_trie_paths_to_not_hash: Default::default(),
            _key_type: PhantomData,
        }
    }
}

impl<K> Trie for MptTrie<K>
where
    K: Into<WrappedNibbles>,
{
    type Key = K;
    type SubTrie = Self;

    fn trie_contains(&self, k: Self::Key) -> bool {
        self.trie.get(k.into().0).is_some()
    }

    /// If a branch collapse occurred after a delete, then we must ensure that
    /// the other single child that remains also is not hashed when passed into
    /// plonky2. Returns the key to the remaining child if a collapse occurred.
    fn trie_delete(&mut self, k: Self::Key) -> TraceDecodingResult<()> {
        let k_nibs = k.into();

        let old_trace = Self::get_trie_trace(&self.trie, &k_nibs.0);
        self.trie.delete(k_nibs.0)?;
        let new_trace = Self::get_trie_trace(&self.trie, &k_nibs.0);

        if let Some(branch_collapse_key) =
            Self::node_deletion_resulted_in_a_branch_collapse(&old_trace, &new_trace)
        {
            self.additional_trie_paths_to_not_hash
                .push(branch_collapse_key);
        }

        Ok(())
    }

    fn trie_create_trie_subset(
        &self,
        ks: impl Iterator<Item = Self::Key>,
        trie_type: TrieType,
    ) -> TraceDecodingResult<Self>
    where
        Self: Sized,
    {
        Ok(create_trie_subset_wrapped(self, ks.map(|k| k.into().0), trie_type)?)
    }

    fn trie_hash(&self) -> TrieRootHash {
        self.trie.hash()
    }
}

impl StateTrie for MptTrie<Address> {
    fn get_account(&self, addr: Address) -> TraceDecodingResult<Option<AccountInfo>> {
        let acc_bytes = self.trie.get(hash_addr_to_nibbles(&addr));

        let res = match acc_bytes {
            Some(bytes) => Some(rlp::decode::<AccountRlp>(bytes).map(|acc_rlp| acc_rlp.into()).map_err(|err| {
                TraceDecodingError::new(TraceDecodingErrorReason::AccountDecode(
                    hex::encode(bytes),
                    err.to_string(),
                ))
            })?),
            None => None,
        };

        Ok(res.into())
    }

    fn set_account(&mut self, addr: Address, acc: &AccountInfo) {
        // Should never be able to fail.
        self.trie.insert(hash_addr_to_nibbles(&addr), rlp::encode(&AccountRlp::from(acc)).to_vec())
            .expect("Failed encoding to rlp encode Account!");
    }
}

impl StorageTrie for MptTrie<StorageAddr> {
    fn set_slot(&mut self, slot: StorageAddr, val: U256) -> TraceDecodingResult<()> {
        self.trie.insert(slot, rlp::encode(&val).to_vec()).map_err(|e| e.into())
    }
    
    fn hash_out_trie(&mut self) -> TraceDecodingResult<()> {
        self.trie = self.trie_create_trie_subset(empty(), TrieType::Storage)?.trie;
        Ok(())
    }
}

impl<T> MptTrie<T> {
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

#[derive(Clone, Debug)]
struct MptGenInputs(GenerationInputs);

impl GenIr for MptGenInputs {
    type TrieRoots = TrieRoots;

    fn get_signed_txn(&self) -> Option<&[u8]> {
        self.0.signed_txn.as_deref()
    }

    fn get_withdrawals_mut(&mut self) -> &mut Vec<(Address, U256)> {
        &mut self.0.withdrawals
    }

    fn update_state_trie_with_subtrie(&mut self, ks: impl Iterator<Item = Address>) -> TraceDecodingResult<()> {
        let mpt_trie: MptStateTrie = WrappedHashedPartialTrie::new(self.0.tries.state_trie.clone()).into();
        let sub_trie = mpt_trie.trie_create_trie_subset(ks, TrieType::State)?;
        self.0.tries.state_trie = sub_trie.trie;

        Ok(())
    }

    fn finalize(self) -> GenerationInputs {
        self.0
    }
}

fn create_minimal_state_partial_trie(
    state_trie: &MptStateTrie,
    state_accesses: impl Iterator<Item = Address>,
) -> TraceDecodingResult<MptStateTrie> {
    create_trie_subset_wrapped(
        state_trie,
        state_accesses.map(|k| hash_addr_to_nibbles(&k)),
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

fn create_minimal_storage_partial_tries<'a>(
    storage_tries: &MptStorageTries,
    accesses_per_account: impl Iterator<
        Item = (
            HashedAccountAddr,
            impl Iterator<Item = StorageAddr>,
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

            let slots_to_not_hash = mem_accesses.map(|k| hash_slot_to_nibbles(&k)).chain(
                base_storage_trie
                    .additional_trie_paths_to_not_hash
                    .iter()
                    .cloned()
            );

            let partial_storage_trie = create_trie_subset_wrapped(
                base_storage_trie,
                slots_to_not_hash,
                TrieType::Storage,
            )?;

            Ok((h_addr, partial_storage_trie))
        })
        .collect::<TraceDecodingResult<_>>()
}

// We really want to get a trie with just a hash node here, and this is an easy
// way to do it.
pub(crate) fn create_fully_hashed_out_sub_partial_trie<T>(
    trie: &T,
    trie_type: TrieType,
) -> <T as Trie>::SubTrie
where
    T: Trie
{
    // Impossible to actually fail with an empty iter.
    trie.trie_create_trie_subset(empty(), trie_type)
        .unwrap()
}

fn create_dummy_proof_tries_mpt(
    final_tries_at_end_of_block: &MptTrieState,
    state_trie: MptStateTrie,
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

fn create_trie_subset_wrapped<T, U>(
    trie: &T,
    ks: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceDecodingResult<U>
where
    T: Deref<Target = HashedPartialTrie>,
    U: From<HashedPartialTrie>,
{
    let trie = create_trie_subset(trie.deref(), ks).map_err(|trie_err| {
        let key = match trie_err {
            SubsetTrieError::UnexpectedKey(key, _) => key,
        };

        TraceDecodingError::new(
            TraceDecodingErrorReason::MissingKeysCreatingSubPartialTrie(key, trie_type),
        )
    })?;

    Ok(U::from(trie))
}
