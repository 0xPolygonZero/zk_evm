use std::marker::PhantomData;

use ethereum_types::U256;
use evm_arithmetization::world::tries::{ReceiptTrie, TransactionTrie};

use crate::core::IntraBlockTries;

/// Observer API for the trace decoder.
/// Observer is used to collect various debugging and metadata info
/// from the trace decoder run.
pub trait Observer<WorldT> {
    /// Collect tries after the transaction/batch execution.
    ///
    /// Passing the arguments one by one through reference, because
    /// we don't want to clone argument tries in case they are not used in
    /// observer.
    fn collect_tries(
        &mut self,
        block: U256,
        batch: usize,
        state_trie: &WorldT,
        transaction_trie: &TransactionTrie,
        receipt_trie: &ReceiptTrie,
    );
}

#[derive(Debug)]
/// Tries observer collected data element - contains
/// the data collected during the trace decoder processing of the batches in a
/// block, one element is retrieved after every batch.
pub struct TriesObserverElement<StateTrieT> {
    /// Block where the tries are collected.
    pub block: U256,
    /// Tries were collected after trace decoder processes batch number `batch`.
    pub batch: usize,
    /// State, transaction, and receipt tries after the batch
    /// execution (how the trace decoder sees them).
    pub tries: IntraBlockTries<StateTrieT>,
}

/// Observer for collection of post-execution tries from the
/// trace decoder run.
#[derive(Debug)]
pub struct TriesObserver<StateTrieT> {
    /// Collected data in the observer pass
    pub data: Vec<TriesObserverElement<StateTrieT>>,
}

impl<StateTrieT> TriesObserver<StateTrieT> {
    /// Create new tries collecting observer.
    pub fn new() -> Self {
        TriesObserver::<StateTrieT> { data: Vec::new() }
    }
}

impl<WorldT: Clone> Observer<WorldT> for TriesObserver<WorldT> {
    fn collect_tries(
        &mut self,
        block: U256,
        batch: usize,
        state_trie: &WorldT,
        transaction_trie: &TransactionTrie,
        receipt_trie: &ReceiptTrie,
    ) {
        self.data.push(TriesObserverElement {
            block,
            batch,
            tries: IntraBlockTries {
                world: state_trie.clone(),
                transaction: transaction_trie.clone(),
                receipt: receipt_trie.clone(),
            },
        });
    }
}

impl<StateTrieT> Default for TriesObserver<StateTrieT> {
    fn default() -> Self {
        Self::new()
    }
}

/// Dummy observer which does not collect any data.
#[derive(Default, Debug)]
pub struct DummyObserver<StateTrieT> {
    phantom: PhantomData<StateTrieT>,
}

impl<StateTrieT> DummyObserver<StateTrieT> {
    /// Create a new dummy observer.
    pub fn new() -> Self {
        DummyObserver::<StateTrieT> {
            phantom: Default::default(),
        }
    }
}

impl<WorldT> Observer<WorldT> for DummyObserver<WorldT> {
    fn collect_tries(
        &mut self,
        _block: U256,
        _batch: usize,
        _state_trie: &WorldT,
        _transaction_trie: &TransactionTrie,
        _receipt_trie: &ReceiptTrie,
    ) {
    }
}
