use std::marker::PhantomData;

use ethereum_types::U256;

use crate::core::IntraBlockTries;
use crate::tries::{ReceiptTrie, TransactionTrie};

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
        world: &WorldT,
        transaction_trie: &TransactionTrie,
        receipt_trie: &ReceiptTrie,
    );
}

#[derive(Debug)]
/// Tries observer collected data element - contains
/// the data collected during the trace decoder processing of the batches in a
/// block, one element is retrieved after every batch.
pub struct TriesObserverElement<WorldT> {
    /// Block where the tries are collected.
    pub block: U256,
    /// Tries were collected after trace decoder processes batch number `batch`.
    pub batch: usize,
    /// State, transaction, and receipt tries after the batch
    /// execution (how the trace decoder sees them).
    pub tries: IntraBlockTries<WorldT>,
}

/// Observer for collection of post-execution tries from the
/// trace decoder run.
#[derive(Debug)]
pub struct TriesObserver<WorldT> {
    /// Collected data in the observer pass
    pub data: Vec<TriesObserverElement<WorldT>>,
}

impl<WorldT> TriesObserver<WorldT> {
    /// Create new tries collecting observer.
    pub fn new() -> Self {
        TriesObserver::<WorldT> { data: Vec::new() }
    }
}

impl<WorldT: Clone> Observer<WorldT> for TriesObserver<WorldT> {
    fn collect_tries(
        &mut self,
        block: U256,
        batch: usize,
        world: &WorldT,
        transaction_trie: &TransactionTrie,
        receipt_trie: &ReceiptTrie,
    ) {
        self.data.push(TriesObserverElement {
            block,
            batch,
            tries: IntraBlockTries {
                world: world.clone(),
                transaction: transaction_trie.clone(),
                receipt: receipt_trie.clone(),
            },
        });
    }
}

impl<WorldT> Default for TriesObserver<WorldT> {
    fn default() -> Self {
        Self::new()
    }
}

/// Dummy observer which does not collect any data.
#[derive(Default, Debug)]
pub struct DummyObserver<WorldT> {
    phantom: PhantomData<WorldT>,
}

impl<WorldT> DummyObserver<WorldT> {
    /// Create a new dummy observer.
    pub fn new() -> Self {
        DummyObserver::<WorldT> {
            phantom: Default::default(),
        }
    }
}

impl<WorldT> Observer<WorldT> for DummyObserver<WorldT> {
    fn collect_tries(
        &mut self,
        _block: U256,
        _batch: usize,
        _world: &WorldT,
        _transaction_trie: &TransactionTrie,
        _receipt_trie: &ReceiptTrie,
    ) {
    }
}
