use std::{
    collections::HashMap, fmt::{self, Display, Formatter}, iter::{self, empty}
};

use ethereum_types::{Address, U256, U512};
use keccak_hash::H256;
use log::trace;
use mpt_trie::{
    nibbles::Nibbles, trie_ops::{TrieOpError, ValOrHash}
};
use thiserror::Error;

use crate::{
    aliased_crate_types::{AccountRlp, BlockHashes, BlockMetadata, ExtraBlockData, TrieRoots},
    compact::compact_processing_common::CompactParsingError,
    processed_block_trace::{
        NodesUsedByTxn, ProcessedBlockTrace, ProcessedTxnInfo, StateTrieWrites,
    },
    types::{
        HashedAccountAddr, HashedNodeAddr, HashedStorageAddr, OtherBlockData, TrieRootHash, TxnIdx,
        EMPTY_TRIE_HASH, ZERO_STORAGE_SLOT_VAL_RLPED,
    },
    utils::{hash, optional_field, optional_field_hex, update_val_if_some},
};

/// Result alias for any operation that may fail related to decoding.
pub type TraceDecodingResult<T> = Result<T, TraceDecodingError>;

pub(crate) trait ProcessedBlockTraceDecode {
    type Spec;
    type Ir: GenIr<StateTrie = Self::StateTrie>;
    type TrieInputs;
    type StateTrie: Trie + StateTrie + Clone;
    type StorageTries: StorageTries + Clone;
    type ReceiptTrie: Trie + Clone;
    type TxnTrie: Trie + Clone;

    fn get_trie_pre_image(spec: &Self::Spec) -> TrieState<Self>;

    fn create_trie_subsets(
        tries: &TrieState<Self>,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
    ) -> TraceDecodingResult<TrieState<Self>>;

    fn create_dummy_ir(
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_tries: &TrieState<Self>,
        account_addrs_accessed: impl Iterator<Item = HashedAccountAddr>,
    ) -> Self::Ir;

    fn create_trie_inputs(tries: TrieState<Self>) -> Self::TrieInputs;

    fn create_ir(
        txn_number_before: U256,
        gas_used_before: U256,
        gas_used_after: U256,
        signed_txn: Option<Vec<u8>>,
        withdrawals: Vec<(Address, U256)>,
        tries: Self::TrieInputs,
        trie_roots_after: TrieRoots,
        checkpoint_state_trie_root: TrieRootHash,
        contract_code: HashMap<H256, Vec<u8>>,
        block_metadata: BlockMetadata,
        block_hashes: BlockHashes,
    ) -> Self::Ir;
}

pub(crate) trait GenIr {
    type TrieRoots;
    type StateTrie: Trie + Clone;
    type StateTrieRef: Into<Self::StateTrie> + StateTrie;

    fn get_signed_txn(&self) -> Option<&[u8]>;
    fn get_withdrawals_mut(&mut self) -> &mut Vec<(Address, U256)>;

    fn get_state_trie_mut(&mut self) -> &mut Self::StateTrieRef;

    fn get_final_trie_roots_mut(&mut self) -> &mut TrieRoots;
}

/// Wrapper to reduce the otherwise extreme verbosity.
pub(crate) type TrieState<D> = TrieStateIntern<
    <D as ProcessedBlockTraceDecode>::StateTrie,
    <D as ProcessedBlockTraceDecode>::StorageTries,
    <D as ProcessedBlockTraceDecode>::ReceiptTrie,
    <D as ProcessedBlockTraceDecode>::TxnTrie,
>;

#[derive(Clone, Debug)]
pub(crate) struct TrieStateIntern<A, B, C, D>
where
    A: Trie + StateTrie + Clone,
    B: StorageTries + Clone,
    C: Trie + Clone,
    D: Trie + Clone,
{
    pub(crate) state: A,
    pub(crate) storage: B,
    pub(crate) receipt: C,
    pub(crate) txn: D,
}

/// Trait just to identify primitive trie-like operations between mpt & smt
/// counterparts. Note that [`HashedPartialTrie`] also implements this directly,
/// so we need to append the redundant `trie_` prefixes to avoid name collisions
/// with the [`PartialTrie`] trie from `mpt_trie`.
pub(crate) trait Trie {
    fn trie_contains(&self, k: Nibbles) -> bool;
    fn trie_get(&self, k: Nibbles) -> Option<&[u8]>;
    fn trie_insert<V: Into<NodeInsertType>>(&mut self, k: Nibbles, v: V)
        -> TraceDecodingResult<()>;
    fn trie_delete(&mut self, k: Nibbles) -> TraceDecodingResult<()>;
    fn trie_create_trie_subset(
        &self,
        ks: impl Iterator<Item = Nibbles>,
        trie_type: TrieType,
    ) -> TraceDecodingResult<Self>
    where
        Self: Sized;
    fn trie_hash(&self) -> TrieRootHash;
}

pub(crate) trait StorageTries {
    type StorageTrie: Trie;

    fn get_trie(&self, h_addr: &HashedAccountAddr) -> Option<&Self::StorageTrie>;
    fn get_mut_trie(&mut self, h_addr: &HashedAccountAddr) -> Option<&mut Self::StorageTrie>;
    fn get_trie_or_create_mut(&mut self, h_addr: &HashedAccountAddr) -> &mut Self::StorageTrie;

    /// Attempts to remove the trie with the given key and returns true if it
    /// was found.
    fn remove_trie(&mut self, addr: &HashedAccountAddr) -> bool;
}

// Extra helper functions for the state trie.
pub(crate) trait StateTrie: Trie {
    fn get_account(&self, addr: Nibbles) -> TraceDecodingResult<Option<AccountRlp>>;
    fn set_account(&mut self, addr: Nibbles, acc: &AccountRlp);
}

/// Identical to `mpt_trie`'s [`ValOrHash`], but we need to also use this type
/// with `smt_trie`.
#[derive(Debug)]
pub(crate) enum NodeInsertType {
    Val(Vec<u8>),
    Hash(H256),
}

impl From<NodeInsertType> for ValOrHash {
    fn from(v: NodeInsertType) -> Self {
        match v {
            NodeInsertType::Val(v) => Self::Val(v),
            NodeInsertType::Hash(h) => Self::Hash(h),
        }
    }
}

impl From<Vec<u8>> for NodeInsertType {
    fn from(value: Vec<u8>) -> Self {
        Self::Val(value)
    }
}

impl From<&[u8]> for NodeInsertType {
    fn from(value: &[u8]) -> Self {
        Self::Val(value.to_vec())
    }
}

impl From<H256> for NodeInsertType {
    fn from(hash: H256) -> Self {
        Self::Hash(hash)
    }
}

// TODO: Make this also work with SMT decoding...
/// Represents errors that can occur during the processing of a block trace.
///
/// This struct is intended to encapsulate various kinds of errors that might
/// arise when parsing, validating, or otherwise processing the trace data of
/// blockchain blocks. It could include issues like malformed trace data,
/// inconsistencies found during processing, or any other condition that
/// prevents successful completion of the trace processing task.
#[derive(Clone, Debug)]
pub struct TraceDecodingError {
    block_num: Option<U256>,
    block_chain_id: Option<U256>,
    txn_idx: Option<usize>,
    addr: Option<Address>,
    h_addr: Option<H256>,
    slot: Option<U512>,
    slot_value: Option<U512>,
    reason: TraceDecodingErrorReason, // The original error type
}

impl Display for TraceDecodingError {
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

impl std::error::Error for TraceDecodingError {}

impl TraceDecodingError {
    /// Function to create a new TraceDecodingError with mandatory fields
    pub(crate) fn new(reason: TraceDecodingErrorReason) -> Self {
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
#[derive(Clone, Debug, Error)]
pub enum TraceDecodingErrorReason {
    /// Failure to decode an Ethereum [Account].
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
    #[error("Missing key {0:x}  when creating sub-partial tries (Trie type: {1})")]
    MissingKeysCreatingSubPartialTrie(Nibbles, TrieType),

    /// Failure due to trying to withdraw from a missing account
    #[error("No account present at {0:x} (hashed: {1:x}) to withdraw {2} Gwei from!")]
    MissingWithdrawalAccount(Address, HashedAccountAddr, U256),

    /// Failure due to a trie operation error.
    #[error("Trie operation error: {0}")]
    TrieOpError(TrieOpError),

    /// Failure due to a compact parsing error.
    #[error("Compact parsing error: {0}")]
    CompactDecodingError(CompactParsingError),

    /// Currently the SMT library does not produce errors, so as a last resort,
    /// we can create string errors hinting at what might have gone wrong.
    #[error("{0}")]
    Other(String),
}

impl From<TrieOpError> for TraceDecodingError {
    fn from(err: TrieOpError) -> Self {
        // Convert TrieOpError into TraceDecodingError
        TraceDecodingError::new(TraceDecodingErrorReason::TrieOpError(err))
    }
}

impl From<CompactParsingError> for TraceDecodingError {
    fn from(err: CompactParsingError) -> Self {
        // Convert CompactParsingError into TraceDecodingError
        TraceDecodingError::new(TraceDecodingErrorReason::CompactDecodingError(err))
    }
}

impl From<TraceDecodingErrorReason> for TraceDecodingError {
    fn from(v: TraceDecodingErrorReason) -> Self {
        Self::new(v)
    }
}

/// An enum to cover all Ethereum trie types (see https://ethereum.github.io/yellowpaper/paper.pdf for details).
#[derive(Clone, Copy, Debug)]
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

impl<T, D> ProcessedBlockTrace<T, D>
where
    D: ProcessedBlockTraceDecode<Spec = T>,
{
    pub(crate) fn into_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<D::Ir>> {
        let mut curr_block_tries = D::get_trie_pre_image(&self.spec);

        // This is just a copy of `curr_block_tries`.
        // TODO: Check if we can remove these clones before PR merge...
        let initial_tries_for_dummies = curr_block_tries.clone();

        let mut extra_data = ExtraBlockData {
            checkpoint_state_trie_root: other_data.checkpoint_state_trie_root,
            txn_number_before: U256::zero(),
            txn_number_after: U256::zero(),
            gas_used_before: U256::zero(),
            gas_used_after: U256::zero(),
        };

        // A copy of the initial extra_data possibly needed during padding.
        let extra_data_for_dummies = extra_data.clone();

        let mut ir = self
            .txn_info
            .into_iter()
            .enumerate()
            .map(|(txn_idx, sect_info)| {
                Self::process_txn_info(
                    txn_idx,
                    sect_info,
                    &mut curr_block_tries,
                    &mut extra_data,
                    &other_data,
                )
                .map_err(|mut e| {
                    e.txn_idx(txn_idx);
                    e
                })
            })
            .collect::<TraceDecodingResult<Vec<_>>>()
            .map_err(|mut e| {
                e.block_num(other_data.b_data.b_meta.block_number);
                e.block_chain_id(other_data.b_data.b_meta.block_chain_id);
                e
            })?;

        Self::pad_gen_inputs_with_dummy_inputs_if_needed(
            &mut ir,
            &other_data,
            &extra_data,
            &extra_data_for_dummies,
            &initial_tries_for_dummies,
            &curr_block_tries,
        );

        if !self.withdrawals.is_empty() {
            Self::add_withdrawals_to_txns(
                &mut ir,
                &mut curr_block_tries.state,
                self.withdrawals.clone(),
            )?;
        }

        Ok(ir)
    }

    fn update_txn_and_receipt_tries(
        receipt_trie: &mut D::ReceiptTrie,
        txn_trie: &mut D::TxnTrie,
        meta: &TxnMetaState,
        txn_idx: TxnIdx,
    ) {
        let txn_k = Nibbles::from_bytes_be(&rlp::encode(&txn_idx)).unwrap();

        txn_trie.trie_insert(txn_k, meta.txn_bytes());
        receipt_trie.trie_insert(txn_k, meta.receipt_node_bytes.as_ref());
    }

    /// If the account does not have a storage trie or does but is not
    /// accessed by any txns, then we still need to manually create an entry for
    /// them.
    fn init_any_needed_empty_storage_tries<'a>(
        storage_tries: &mut D::StorageTries,
        accounts_with_storage: impl Iterator<Item = &'a HashedStorageAddr>,
        state_accounts_with_no_accesses_but_storage_tries: &'a HashMap<
            HashedAccountAddr,
            TrieRootHash,
        >,
    ) {
        for h_addr in accounts_with_storage {
            if storage_tries.get_trie(h_addr).is_none() {
                // If the account does not have accesses but has storage that is not accessed,
                // then we still need to create a hashed out storage trie for the account.
                let trie_root_hash = state_accounts_with_no_accesses_but_storage_tries
                    .get(h_addr)
                    .map(|s_root| hash(s_root.as_bytes()))
                    .unwrap_or_else(|| EMPTY_TRIE_HASH);

                let trie = storage_tries.get_trie_or_create_mut(h_addr);
                trie.trie_insert(Nibbles::default(), NodeInsertType::Hash(trie_root_hash));
            };
        }
    }

    fn apply_deltas_to_trie_state(
        trie_state: &mut TrieState<D>,
        deltas: &NodesUsedByTxn,
        meta: &TxnMetaState,
    ) -> TraceDecodingResult<()> {
        for (hashed_acc_addr, storage_writes) in deltas.storage_writes.iter() {
            let storage_trie = trie_state
                .storage
                .get_mut_trie(hashed_acc_addr)
                .ok_or_else(|| {
                    let hashed_acc_addr = *hashed_acc_addr;
                    let mut e = TraceDecodingError::new(
                        TraceDecodingErrorReason::MissingAccountStorageTrie(hashed_acc_addr),
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
                    false => storage_trie
                        .trie_insert(slot, val.clone())
                        .map_err(|mut e| {
                            e.slot(U512::from_big_endian(slot.bytes_be().as_slice()));
                            e.slot_value(U512::from_big_endian(val.as_slice()));
                            e
                        })?,
                    true => {
                        storage_trie.trie_delete(slot)?;
                    }
                };
            }
        }

        for (hashed_acc_addr, s_trie_writes) in deltas.state_writes.iter() {
            let val_k = Nibbles::from_h256_be(*hashed_acc_addr);

            // If the account was created, then it will not exist in the trie.
            let mut account = trie_state.state.get_account(val_k)?.unwrap_or_default();

            s_trie_writes.apply_writes_to_state_node::<D>(
                &mut account,
                hashed_acc_addr,
                &trie_state.storage,
            )?;

            let updated_account_bytes = rlp::encode(&account);
            trie_state
                .state
                .trie_insert(val_k, updated_account_bytes.to_vec());
        }

        // Remove any accounts that self-destructed.
        for hashed_addr in deltas.self_destructed_accounts.iter() {
            let k = Nibbles::from_h256_be(*hashed_addr);

            if !trie_state.storage.remove_trie(hashed_addr) {
                let hashed_addr = *hashed_addr;
                let mut e = TraceDecodingError::new(
                    TraceDecodingErrorReason::MissingAccountStorageTrie(hashed_addr),
                );
                e.h_addr(hashed_addr);

                return Err(e);
            };

            // TODO: Once the mechanism for resolving code hashes settles, we probably want
            // to also delete the code hash mapping here as well...

            trie_state.state.trie_delete(k)?;
        }

        Ok(())
    }

    /// Pads a generated IR vec with additional "dummy" entries if needed.
    /// We need to ensure that generated IR always has at least `2` elements,
    /// and if there are only `0` or `1` elements, then we need to pad so
    /// that we have two entries in total. These dummy entries serve only to
    /// allow the proof generation process to finish. Specifically, we need
    /// at least two entries to generate an agg proof, and we need an agg
    /// proof to generate a block proof. These entries do not mutate state.
    fn pad_gen_inputs_with_dummy_inputs_if_needed(
        gen_inputs: &mut Vec<D::Ir>,
        other_data: &OtherBlockData,
        final_extra_data: &ExtraBlockData,
        initial_extra_data: &ExtraBlockData,
        initial_tries: &TrieState<D>,
        final_tries: &TrieState<D>,
    ) {
        match gen_inputs.len() {
            0 => {
                debug_assert!(initial_tries.state.trie_hash() == final_tries.state.trie_hash());
                debug_assert!(initial_extra_data == final_extra_data);
                // We need to pad with two dummy entries.
                gen_inputs.extend(Self::create_dummy_txn_pair_for_empty_block(
                    other_data,
                    final_extra_data,
                    initial_tries,
                ));
            }
            1 => {
                // We just need one dummy entry.
                // The dummy proof will be prepended to the actual txn.
                let dummy_txn =
                    D::create_dummy_ir(other_data, initial_extra_data, initial_tries, empty());
                gen_inputs.insert(0, dummy_txn)
            }
            _ => (),
        }
    }

    /// The withdrawals are always in the final ir payload.
    fn add_withdrawals_to_txns(
        txn_ir: &mut [D::Ir],
        final_trie_state: &mut D::StateTrie,
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

        if last_inputs.get_signed_txn().is_none() {
            // This is a dummy payload, hence it does not contain yet
            // state accesses to the withdrawal addresses.
            let withdrawal_addrs =
                withdrawals_with_hashed_addrs_iter().map(|(_, h_addr, _)| h_addr);

            let state_trie_ref = last_inputs.get_state_trie_mut();

            let sub_state_trie = Self::create_minimal_state_partial_trie(
                state_trie_ref,
                withdrawal_addrs,
                iter::empty(),
            )?;

            *state_trie_ref = sub_state_trie;
        }

        Self::update_trie_state_from_withdrawals(
            withdrawals_with_hashed_addrs_iter(),
            final_trie_state,
        )?;

        *last_inputs.get_withdrawals_mut() = withdrawals;
        last_inputs.get_final_trie_roots_mut().state_root = final_trie_state.trie_hash();

        Ok(())
    }

    /// Withdrawals update balances in the account trie, so we need to update
    /// our local trie state.
    fn update_trie_state_from_withdrawals<'a>(
        withdrawals: impl IntoIterator<Item = (Address, HashedAccountAddr, U256)> + 'a,
        state: &mut D::StateTrie,
    ) -> TraceDecodingResult<()> {
        for (addr, h_addr, amt) in withdrawals {
            let h_addr_nibs = Nibbles::from_h256_be(h_addr);

            let mut acc_data = state
                .get_account(h_addr_nibs)
                .map_err(|e| Self::add_addr_and_h_addr_to_trace_error(e, addr, h_addr))?
                .ok_or_else(|| {
                    Self::add_addr_and_h_addr_to_trace_error(
                        TraceDecodingErrorReason::MissingWithdrawalAccount(addr, h_addr, amt)
                            .into(),
                        addr,
                        h_addr,
                    )
                })?;

            acc_data.balance += amt;

            state.trie_insert(h_addr_nibs, rlp::encode(&acc_data).to_vec());
        }

        Ok(())
    }

    fn add_addr_and_h_addr_to_trace_error(
        mut e: TraceDecodingError,
        addr: Address,
        h_addr: HashedAccountAddr,
    ) -> TraceDecodingError {
        e.addr(addr);
        e.h_addr(h_addr);

        e
    }

    /// Processes a single transaction in the trace.
    fn process_txn_info(
        txn_idx: usize,
        txn_info: ProcessedTxnInfo,
        curr_block_tries: &mut TrieState<D>,
        extra_data: &mut ExtraBlockData,
        other_data: &OtherBlockData,
    ) -> TraceDecodingResult<D::Ir> {
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

        Self::update_txn_and_receipt_tries(
            &mut curr_block_tries.receipt,
            &mut curr_block_tries.txn,
            &txn_info.meta,
            txn_idx,
        );

        Self::apply_deltas_to_trie_state(
            curr_block_tries,
            &txn_info.nodes_used_by_txn,
            &txn_info.meta,
        )?;

        let tries = D::create_trie_subsets(curr_block_tries, &txn_info.nodes_used_by_txn, txn_idx)?;

        let trie_roots_after = Self::calculate_trie_input_hashes(curr_block_tries);

        let gen_inputs = D::create_ir(
            extra_data.txn_number_before,
            extra_data.gas_used_before,
            extra_data.gas_used_after,
            txn_info.meta.txn_bytes,
            Vec::default(),
            D::create_trie_inputs(tries),
            trie_roots_after,
            extra_data.checkpoint_state_trie_root,
            txn_info.contract_code_accessed,
            other_data.b_data.b_meta.clone(),
            other_data.b_data.b_hashes.clone(),
        );

        // After processing a transaction, we update the remaining accumulators
        // for the next transaction.
        extra_data.txn_number_before += U256::one();
        extra_data.gas_used_before = extra_data.gas_used_after;

        Ok(gen_inputs)
    }

    fn create_minimal_state_partial_trie<U: StateTrie>(
        state_trie: &U,
        state_accesses: impl Iterator<Item = HashedNodeAddr>,
        additional_state_trie_paths_to_not_hash: impl Iterator<Item = Nibbles>,
    ) -> TraceDecodingResult<U> {
        create_trie_subset_wrapped(
            state_trie,
            state_accesses
                .into_iter()
                .map(Nibbles::from_h256_be)
                .chain(additional_state_trie_paths_to_not_hash),
            TrieType::State,
        )
    }

    fn calculate_trie_input_hashes(t_inputs: &TrieState<D>) -> TrieRoots {
        TrieRoots {
            state_root: t_inputs.state.trie_hash(),
            transactions_root: t_inputs.txn.trie_hash(),
            receipts_root: t_inputs.receipt.trie_hash(),
        }
    }

    fn create_dummy_txn_pair_for_empty_block(
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_tries: &TrieState<D>,
    ) -> [D::Ir; 2] {
        [
            D::create_dummy_ir(other_data, extra_data, final_tries, empty()),
            D::create_dummy_ir(other_data, extra_data, final_tries, empty()),
        ]
    }
}

impl StateTrieWrites {
    fn apply_writes_to_state_node<D: ProcessedBlockTraceDecode>(
        &self,
        state_node: &mut AccountRlp,
        h_addr: &HashedAccountAddr,
        storage_tries: &D::StorageTries,
    ) -> TraceDecodingResult<()> {
        let storage_root_hash_change = match self.storage_trie_change {
            false => None,
            true => {
                let storage_trie = storage_tries.get_trie(h_addr).ok_or_else(|| {
                    let h_addr = *h_addr;
                    let mut e = TraceDecodingError::new(
                        TraceDecodingErrorReason::MissingAccountStorageTrie(h_addr),
                    );
                    e.h_addr(h_addr);
                    e
                })?;

                Some(storage_trie.trie_hash())
            }
        };

        update_val_if_some(&mut state_node.balance, self.balance);
        update_val_if_some(&mut state_node.nonce, self.nonce);
        update_val_if_some(&mut state_node.storage_root, storage_root_hash_change);
        update_val_if_some(&mut state_node.code_hash, self.code_hash);

        Ok(())
    }
}

pub(crate) fn create_trie_subset_wrapped<U: Trie>(
    trie: &U,
    accesses: impl Iterator<Item = Nibbles>,
    trie_type: TrieType,
) -> TraceDecodingResult<U> {
    trie.trie_create_trie_subset(accesses, trie_type)
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
