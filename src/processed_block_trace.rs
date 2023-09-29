use std::collections::HashMap;

use eth_trie_utils::partial_trie::HashedPartialTrie;

use crate::trace_protocol::{
    BlockTrace, BlockUsedContractCode, StorageTriesPreImage, TrieCompact, TriePreImage, TxnInfo,
};
use crate::types::{CodeHash, HashedAccountAddress};

pub(crate) struct ProcessedBlockTrace {
    state_trie: HashedPartialTrie,
    storage_tries: HashMap<HashedAccountAddress, HashedPartialTrie>,
    contract_code: HashMap<CodeHash, Vec<u8>>,
    txn_info: Vec<TxnInfo>,
}

impl BlockTrace {
    fn into_processed_block_trace<F>(self, p_meta: &ProcessingMeta<F>) -> ProcessedBlockTrace
    where
        F: Fn(&CodeHash) -> Vec<u8>,
    {
        ProcessedBlockTrace {
            state_trie: process_state_trie(self.state_trie),
            storage_tries: process_storage_tries(self.storage_tries),
            contract_code: process_block_used_contract_code(
                self.contract_code,
                &p_meta.resolve_code_hash_fn,
            ),
            txn_info: self.txn_info,
        }
    }
}

fn process_state_trie(trie: TriePreImage) -> HashedPartialTrie {
    match trie {
        TriePreImage::Uncompressed(_) => todo!(),
        TriePreImage::Compact(t) => process_compact_trie(t),
        TriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: StorageTriesPreImage,
) -> HashMap<HashedAccountAddress, HashedPartialTrie> {
    match trie {
        StorageTriesPreImage::SingleTrie(t) => process_single_storage_trie(t),
        StorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_storage_trie(
    _trie: TriePreImage,
) -> HashMap<HashedAccountAddress, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddress, TriePreImage>,
) -> HashMap<HashedAccountAddress, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(_trie: TrieCompact) -> HashedPartialTrie {
    todo!()
}

fn process_block_used_contract_code<F>(
    code: BlockUsedContractCode,
    resolve_code_hash_fn: &F,
) -> HashMap<CodeHash, Vec<u8>>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    match code {
        BlockUsedContractCode::Full(c) => c,
        BlockUsedContractCode::Digests(d) => {
            let code_hash_to_code_iter = d
                .into_iter()
                .map(|c_hash| (c_hash, resolve_code_hash_fn(&c_hash)));
            HashMap::from_iter(code_hash_to_code_iter)
        }
    }
}

#[derive(Debug)]
pub struct ProcessingMeta<F>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    resolve_code_hash_fn: F,
}

impl<F> ProcessingMeta<F>
where
    F: Fn(&CodeHash) -> Vec<u8>,
{
    pub fn new(resolve_code_hash_fn: F) -> Self {
        Self {
            resolve_code_hash_fn,
        }
    }
}
