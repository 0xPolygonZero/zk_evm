use std::{
    borrow::{Borrow, BorrowMut},
    cell::{Cell, Ref, RefCell},
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    rc::Rc,
};

use ethereum_types::{Address, H160, U256};
use keccak_hash::H256;
use plonky2::plonk::config::GenericHashOut;
use smt_trie::{
    db::MemoryDb,
    keys::{key_balance, key_code, key_nonce, key_storage},
    smt::{hash_serialize, Smt},
};

use crate::aliased_crate_types::HashedPartialTrie;
use crate::{
    aliased_crate_types::{
        BlockHashes, BlockMetadata, ExtraBlockData, GenerationInputs, TrieInputs, TrieRoots,
    },
    decoding::{
        calculate_trie_root_hashes, GenIr, NodeInsertType, ProcessedBlockTraceDecode, StateTrie,
        StorageTrie, StorageTries, TraceDecodingResult, Trie, TrieState, TrieType,
        WrappedHashedPartialTrie,
    },
    processed_block_trace::{NodesUsedByTxn, ProcessingMeta},
    processed_block_trace_smt::{ProcedBlockTraceSmtSpec, SmtProcessedBlockTrace},
    trace_protocol::BlockTrace,
    types::{
        AccountInfo, CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedStorageAddr,
        OtherBlockData, StorageAddr, TrieRootHash, TxnIdx,
    },
};

pub(crate) type SmtTrieInner = Smt<MemoryDb>;
pub(crate) type SmtKey = smt_trie::smt::Key;
type SmtSubTrie = Vec<U256>;

pub(crate) type SmtStateTrieWrapped = SmtTrieWrapped<SmtStateTrie>;
pub(crate) type SmtStorageTrieWrapped = SmtTrieWrapped<SmtStorageTrie>;
type SmtTrieWrapped<T> = Rc<RefCell<T>>;

#[derive(Clone, Debug)]
struct SmtAccountQuery {
    addr: Address,
    balance: bool,
    nonce: bool,
    c_hash: bool,
}

impl From<Address> for SmtAccountQuery {
    fn from(v: Address) -> Self {
        Self {
            addr: v,
            balance: true,
            nonce: true,
            c_hash: true,
        }
    }
}

impl From<&Address> for SmtAccountQuery {
    fn from(v: &Address) -> Self {
        Self::from(*v)
    }
}

impl IntoIterator for SmtAccountQuery {
    type Item = SmtKey;

    type IntoIter = SmtAccountQueryIterator;

    fn into_iter(self) -> Self::IntoIter {
        SmtAccountQueryIterator {
            queries: self,
            curr_idx: 0,
        }
    }
}

#[derive(Debug)]
struct SmtAccountQueryIterator {
    queries: SmtAccountQuery,
    curr_idx: usize,
}

impl Iterator for SmtAccountQueryIterator {
    type Item = SmtKey;

    fn next(&mut self) -> Option<Self::Item> {
        while self.curr_idx <= 2 {
            let (should_query_elem, key_f): (_, fn(H160) -> SmtKey) = match self.curr_idx {
                0 => (self.queries.balance, key_balance),
                1 => (self.queries.nonce, key_nonce),
                2 => (self.queries.c_hash, key_code),
                _ => unreachable!(),
            };
            self.curr_idx += 1;

            if should_query_elem {
                return Some(key_f(self.queries.addr));
            }
        }

        None
    }
}

impl BlockTrace {
    pub(crate) fn into_proof_gen_smt_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }
}

pub(crate) struct SmtBlockTraceDecoding;

impl ProcessedBlockTraceDecode for SmtBlockTraceDecoding {
    type Spec = ProcedBlockTraceSmtSpec;
    type Ir = SmtGenInputs;
    type TrieInputs = TrieInputs;
    type StateTrie = SmtStateTrie;
    type StorageTries = SmtStateTrie;
    type ReceiptTrie = WrappedHashedPartialTrie<TxnIdx>;
    type TxnTrie = WrappedHashedPartialTrie<TxnIdx>;

    fn get_trie_pre_image(spec: &Self::Spec) -> TrieState<Self> {
        TrieState {
            state: spec.trie.clone(),
            storage: spec.trie.clone(),
            receipt: HashedPartialTrie::default().into(),
            txn: HashedPartialTrie::default().into(),
        }
    }

    // TODO: Merge?
    /// Not actually used for SMT.
    fn init_any_needed_empty_storage_tries<'a>(
        storage_tries: &mut Self::StorageTries,
        accounts_with_storage: impl Iterator<Item = &'a Address>,
        state_accounts_with_no_accesses_but_storage_tries: &'a HashMap<Address, TrieRootHash>,
    ) {
    }

    fn create_trie_subsets(
        tries: &TrieState<Self>,
        nodes_used_by_txn: &NodesUsedByTxn,
        txn_idx: TxnIdx,
    ) -> TraceDecodingResult<TrieState<Self>> {
        todo!();
    }

    fn create_dummy_ir(
        other_data: &OtherBlockData,
        extra_data: &ExtraBlockData,
        final_tries: &TrieState<Self>,
        account_addrs_accessed: impl Iterator<Item = Address>,
    ) -> Self::Ir {
        todo!()
    }

    fn create_trie_inputs(tries: TrieState<Self>) -> Self::TrieInputs {
        TrieInputs {
            state_smt: tries.state.inner.borrow().serialize(),
            transactions_trie: tries.txn.inner,
            receipts_trie: tries.receipt.inner,
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
        todo!()
    }
}

/// Wrapper type to make it easier to work with consistent types.
#[derive(Debug)]
struct SmtGenInputs {
    intern: GenerationInputs,
    tries: TrieState<SmtBlockTraceDecoding>,

    /// We need to be able to change the trie to be a subtrie in some cases.
    /// However, the subtrie type for `smt_trie` is actually a very different
    /// type from a normal SMT trie, so we need this funny mechanism to be able
    /// to do this.
    state_sub_trie_override: Option<SmtSubTrie>,
}

impl GenIr for SmtGenInputs {
    type TrieRoots = TrieRoots;
    type StateTrie = SmtStateTrie;

    fn get_signed_txn(&self) -> Option<&[u8]> {
        self.intern.signed_txn.as_ref().map(|t| t.as_ref())
    }

    fn get_withdrawals_mut(&mut self) -> &mut Vec<(Address, U256)> {
        &mut self.intern.withdrawals
    }

    fn get_state_trie_mut(&self) -> &Self::StateTrie {
        &self.tries.state
    }

    fn update_trie_with_subtrie(
        &mut self,
        state_sub_trie_override: <Self::StateTrie as Trie>::SubTrie,
    ) {
        self.state_sub_trie_override = Some(state_sub_trie_override)
    }

    fn finalize(mut self) -> GenerationInputs {
        let state_smt = self
            .state_sub_trie_override
            .unwrap_or_else(|| self.tries.state.serialize());

        self.intern.trie_roots_after =
            calculate_trie_root_hashes::<SmtBlockTraceDecoding>(&self.tries);

        self.intern.tries = TrieInputs {
            state_smt,
            transactions_trie: self.tries.txn.inner,
            receipts_trie: self.tries.receipt.inner,
        };

        self.intern
    }
}

#[derive(Clone, Debug)]
struct SmtStateTrie {
    inner: SmtTrieInner,
}

impl<T: Trie> Trie for SmtTrieWrapped<T> {
    type Key = Address;
    type SubTrie = SmtSubTrie;

    fn trie_contains(&self, k: Address) -> bool {
        for field_k in SmtAccountQuery::from(k).into_iter() {
            if !self.borrow().inner.get(field_k).is_zero() {
                return true;
            }
        }

        false
    }

    fn trie_delete(&mut self, k: Address) -> TraceDecodingResult<()> {
        for field_k in SmtAccountQuery::from(k).into_iter() {
            self.borrow_mut().inner.delete(field_k);
        }

        Ok(())
    }

    fn trie_create_trie_subset(
        &self,
        ks: impl Iterator<Item = Self::Key>,
        _: TrieType,
    ) -> TraceDecodingResult<Self::SubTrie>
    where
        Self: Sized,
    {
        let field_ks = ks.map(|k| SmtAccountQuery::from(k).into_iter()).flatten();

        Ok(self.inner.borrow().serialize_and_prune(field_ks))
    }

    fn trie_hash(&self) -> TrieRootHash {
        TrieRootHash::from_slice(&self.inner.borrow().root.to_bytes())
    }
}

impl<T> StateTrie for SmtTrieWrapped<T> {
    fn get_account(&self, addr: Address) -> TraceDecodingResult<Option<AccountInfo>> {
        todo!()
    }

    fn set_account(&mut self, addr: Address, acc: &AccountInfo) {
        todo!()
    }
}

struct SmtStorageTrie {
    trie_ref: Rc<Cell<SmtTrieInner>>,
    storage_trie_root: TrieRootHash,
}

impl Trie for SmtTrieWrapped {
    type Key = StorageAddr;
    type SubTrie = SmtSubTrie;

    fn trie_contains(&self, k: StorageAddr) -> bool {
        todo!()
    }

    fn trie_delete(&mut self, k: StorageAddr) -> TraceDecodingResult<()> {
        todo!()
    }

    fn trie_create_trie_subset(
        &self,
        ks: impl Iterator<Item = Self::Key>,
        trie_type: TrieType,
    ) -> TraceDecodingResult<Self::SubTrie>
    where
        Self: Sized,
    {
        todo!()
    }

    fn trie_hash(&self) -> TrieRootHash {
        todo!()
    }
}

impl StorageTrie for SmtTrieWrapped {
    fn set_slot(&mut self, slot: &StorageAddr, val: U256) -> TraceDecodingResult<()> {
        todo!()
    }
}

impl StorageTries for SmtTrieWrapped {
    // type Key = Address;
    type StorageTrie = SmtTrieWrapped;

    fn get_trie(&self, addr: Address) -> Option<&Self::StorageTrie> {
        todo!()
    }

    fn get_mut_trie(&mut self, addr: Address) -> Option<&mut Self::StorageTrie> {
        todo!()
    }

    fn get_trie_or_create_mut(&mut self, addr: Address) -> &mut Self::StorageTrie {
        todo!()
    }

    fn remove_trie(&mut self, addr: Address) -> bool {
        todo!()
    }
}
