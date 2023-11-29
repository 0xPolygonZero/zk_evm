use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::iter::once;
use std::str::FromStr;

use eth_trie_utils::nibbles::Nibbles;
use eth_trie_utils::partial_trie::{HashedPartialTrie, PartialTrie};
use ethereum_types::U256;
use plonky2_evm::generation::mpt::AccountRlp;

use crate::compact::compact_prestate_processing::{process_compact_prestate, PartialTriePreImages};
use crate::decoding::TraceParsingResult;
use crate::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TrieCompact,
    TrieUncompressed, TxnInfo,
};
use crate::types::{
    Bloom, CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedNodeAddr,
    HashedStorageAddrNibbles, OtherBlockData, StorageAddr, TrieRootHash, TxnProofGenIR,
    EMPTY_CODE_HASH, EMPTY_TRIE_HASH,
};
use crate::utils::{
    hash, print_value_and_hash_nodes_of_storage_trie, print_value_and_hash_nodes_of_trie,
};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace {
    pub(crate) tries: PartialTriePreImages,
    pub(crate) txn_info: Vec<ProcessedTxnInfo>,
}

const COMPATIBLE_HEADER_VERSION: u8 = 1;

impl BlockTrace {
    pub fn into_txn_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceParsingResult<Vec<TxnProofGenIR>>
    where
        F: CodeHashResolveFunc,
    {
        let proced_block_trace = self.into_processed_block_trace(p_meta);
        proced_block_trace.into_txn_proof_gen_ir(other_data)
    }

    fn into_processed_block_trace<F>(self, p_meta: &ProcessingMeta<F>) -> ProcessedBlockTrace
    where
        F: CodeHashResolveFunc,
    {
        // The compact format is able to provide actual code, so if it does, we should
        // take advantage of it.
        let pre_image_data = process_block_trace_trie_pre_images(self.trie_pre_images);

        print_value_and_hash_nodes_of_trie(&pre_image_data.tries.state);

        for (h_addr, s_trie) in pre_image_data.tries.storage.iter() {
            print_value_and_hash_nodes_of_storage_trie(h_addr, s_trie);
        }

        let resolve_code_hash_fn = |c_hash: &_| {
            let resolve_code_hash_fn_ref = &p_meta.resolve_code_hash_fn;
            let extra_code_hash_mappings_ref = &pre_image_data.extra_code_hash_mappings;

            match extra_code_hash_mappings_ref {
                Some(m) => m
                    .get(c_hash)
                    .cloned()
                    .unwrap_or_else(|| (resolve_code_hash_fn_ref)(c_hash)),
                None => (resolve_code_hash_fn_ref)(c_hash),
            }
        };

        let all_accounts_in_pre_image: Vec<_> = pre_image_data
            .tries
            .state
            .items()
            .filter_map(|(addr, data)| {
                data.as_val().map(|data| {
                    (
                        HashedAccountAddr::from_slice(&addr.bytes_be()),
                        rlp::decode::<AccountRlp>(data).unwrap(),
                    )
                })
            })
            .collect();

        let txn_info = self
            .txn_info
            .into_iter()
            .map(|t| t.into_processed_txn_info(&all_accounts_in_pre_image, &resolve_code_hash_fn))
            .collect::<Vec<_>>();

        ProcessedBlockTrace {
            tries: pre_image_data.tries,
            txn_info,
        }
    }
}

#[derive(Debug)]
struct ProcessedBlockTracePreImages {
    tries: PartialTriePreImages,
    extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

fn process_block_trace_trie_pre_images(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> ProcessedBlockTracePreImages {
    match block_trace_pre_images {
        BlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images(t),
        BlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(tries: CombinedPreImages) -> ProcessedBlockTracePreImages {
    process_compact_trie(tries.compact)
}

fn process_separate_trie_pre_images(tries: SeparateTriePreImages) -> ProcessedBlockTracePreImages {
    let tries = PartialTriePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
    };

    ProcessedBlockTracePreImages {
        tries,
        extra_code_hash_mappings: None,
    }
}

fn process_state_trie(trie: SeparateTriePreImage) -> HashedPartialTrie {
    match trie {
        SeparateTriePreImage::Uncompressed(_) => todo!(),
        SeparateTriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: SeparateStorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        SeparateStorageTriesPreImage::SingleTrie(t) => process_single_combined_storage_tries(t),
        SeparateStorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_combined_storage_tries(
    _trie: TrieUncompressed,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, SeparateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(trie: TrieCompact) -> ProcessedBlockTracePreImages {
    // TODO: Wrap in proper result type...
    let out = process_compact_prestate(trie).unwrap();

    // TODO: Make this into a result...
    assert!(out.header.version_is_compatible(COMPATIBLE_HEADER_VERSION));

    ProcessedBlockTracePreImages {
        tries: out.witness_out.tries,
        extra_code_hash_mappings: out.witness_out.code,
    }
}

#[derive(Debug)]
pub struct ProcessingMeta<F>
where
    F: CodeHashResolveFunc,
{
    resolve_code_hash_fn: F,
}

impl<F> ProcessingMeta<F>
where
    F: CodeHashResolveFunc,
{
    pub fn new(resolve_code_hash_fn: F) -> Self {
        Self {
            resolve_code_hash_fn,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessedTxnInfo {
    pub(crate) nodes_used_by_txn: NodesUsedByTxn,
    pub(crate) contract_code_accessed: HashMap<CodeHash, Vec<u8>>,
    pub(crate) meta: TxnMetaState,
}

impl TxnInfo {
    fn into_processed_txn_info<F: CodeHashResolveFunc>(
        self,
        all_accounts_in_pre_image: &[(HashedAccountAddr, AccountRlp)],
        code_hash_resolve_f: &F,
    ) -> ProcessedTxnInfo {
        let mut nodes_used_by_txn = NodesUsedByTxn::default();
        let mut contract_code_accessed = create_empty_code_access_map();

        let block_bloom = self.block_bloom();

        for (addr, trace) in self.traces {
            let hashed_addr = hash(addr.as_bytes());

            let storage_writes = trace.storage_written.unwrap_or_default();

            let storage_read_keys = trace
                .storage_read
                .into_iter()
                .flat_map(|reads| reads.into_iter());

            let storage_write_keys = storage_writes.keys();
            let storage_access_keys = storage_read_keys.chain(storage_write_keys.copied());

            nodes_used_by_txn.storage_accesses.push((
                Nibbles::from_h256_be(hashed_addr),
                storage_access_keys
                    .map(|k| storage_addr_to_nibbles_even_nibble_fixed_hashed(&k))
                    .collect(),
            ));

            let storage_trie_change = !storage_writes.is_empty();
            let code_change = trace.code_usage.is_some();
            let state_write_occurred = trace.balance.is_some()
                || trace.nonce.is_some()
                || storage_trie_change
                || code_change;

            if state_write_occurred {
                let state_trie_writes = StateTrieWrites {
                    balance: trace.balance,
                    nonce: trace.nonce,
                    storage_trie_change,
                    code_hash: trace.code_usage.as_ref().map(|usage| usage.get_code_hash()),
                };

                nodes_used_by_txn
                    .state_writes
                    .push((hashed_addr, state_trie_writes))
            }

            let storage_writes_vec = storage_writes
                .into_iter()
                .map(|(k, v)| (Nibbles::from_h256_be(k), rlp::encode(&v).to_vec()))
                .collect();

            nodes_used_by_txn
                .storage_writes
                .push((Nibbles::from_h256_be(hashed_addr), storage_writes_vec));

            nodes_used_by_txn.state_accesses.push(hashed_addr);

            if let Some(c_usage) = trace.code_usage {
                match c_usage {
                    ContractCodeUsage::Read(c_hash) => {
                        contract_code_accessed
                            .entry(c_hash)
                            .or_insert_with(|| code_hash_resolve_f(&c_hash));
                    }
                    ContractCodeUsage::Write(c_bytes) => {
                        let c_hash = hash(&c_bytes);
                        contract_code_accessed.insert(c_hash, c_bytes.0);
                    }
                }
            }
        }

        // println!(
        //     "Storage accesses for {:x} (hashed: {:x}): {:#?}",
        //     addr, hashed_addr, nodes_used_by_txn
        // );

        let accounts_with_storage_accesses: HashSet<_> = HashSet::from_iter(
            nodes_used_by_txn
                .storage_accesses
                .iter()
                .filter(|(_, slots)| !slots.is_empty())
                .map(|(addr, _)| *addr),
        );
        println!(
            "Account with storage accesses: {:#?}",
            accounts_with_storage_accesses
        );

        let all_accounts_with_non_empty_storage = all_accounts_in_pre_image
            .iter()
            .filter(|(_, data)| data.storage_root != EMPTY_TRIE_HASH);

        let accounts_with_storage_but_no_storage_accesses = all_accounts_with_non_empty_storage
            .filter(|&(addr, _data)| {
                !accounts_with_storage_accesses.contains(&Nibbles::from_h256_be(*addr))
            })
            .map(|(addr, data)| (*addr, data.storage_root));

        nodes_used_by_txn
            .state_accounts_with_no_accesses_but_storage_tries
            .extend(accounts_with_storage_but_no_storage_accesses);

        let receipt_node_bytes = rlp::encode(&self.meta.new_receipt_trie_node_byte).to_vec();

        let txn_bytes = match self.meta.byte_code.is_empty() {
            false => Some(self.meta.byte_code),
            true => None,
        };

        let new_meta_state = TxnMetaState {
            txn_bytes,
            receipt_node_bytes,
            gas_used: self.meta.gas_used,
            block_bloom,
        };

        ProcessedTxnInfo {
            nodes_used_by_txn,
            contract_code_accessed,
            meta: new_meta_state,
        }
    }

    fn block_bloom(&self) -> Bloom {
        let mut bloom = [U256::zero(); 8];

        // Note that bloom can be empty.
        for (i, v) in self
            .meta
            .new_receipt_trie_node_byte
            .bloom
            .clone()
            .into_iter()
            .array_chunks::<32>()
            .enumerate()
        {
            bloom[i] = U256::from_big_endian(v.as_slice());
        }

        bloom
    }
}

fn create_empty_code_access_map() -> HashMap<CodeHash, Vec<u8>> {
    HashMap::from_iter(once((EMPTY_CODE_HASH, Vec::new())))
}

/// Note that "*_accesses" includes writes.
#[derive(Debug, Default)]
pub(crate) struct NodesUsedByTxn {
    pub(crate) state_accesses: Vec<HashedNodeAddr>,
    pub(crate) state_writes: Vec<(HashedAccountAddr, StateTrieWrites)>,

    // Note: All entries in `storage_writes` also appear in `storage_accesses`.
    pub(crate) storage_accesses: Vec<(Nibbles, Vec<HashedStorageAddrNibbles>)>,
    pub(crate) storage_writes: Vec<(Nibbles, Vec<(HashedStorageAddrNibbles, Vec<u8>)>)>,
    pub(crate) state_accounts_with_no_accesses_but_storage_tries:
        HashMap<HashedAccountAddr, TrieRootHash>,
}

#[derive(Debug)]
pub(crate) struct StateTrieWrites {
    pub(crate) balance: Option<U256>,
    pub(crate) nonce: Option<U256>,
    pub(crate) storage_trie_change: bool,
    pub(crate) code_hash: Option<CodeHash>,
}

#[derive(Debug, Default)]
pub(crate) struct TxnMetaState {
    pub(crate) txn_bytes: Option<Vec<u8>>,
    pub(crate) receipt_node_bytes: Vec<u8>,
    pub(crate) gas_used: u64,
    pub(crate) block_bloom: Bloom,
}

// TODO: Remove/rename function based on how complex this gets...
fn storage_addr_to_nibbles_even_nibble_fixed_hashed(addr: &StorageAddr) -> Nibbles {
    // I think this is all we need to do? Yell at me if this breaks things.
    // H256's are never going to be truncated I think.

    // // TODO: Disgusting hack! Remove if this works...
    // let s = hex::encode(addr.as_bytes());

    // let mut n = Nibbles::from_str(&s).unwrap();
    // let odd_count = (n.count & 1) == 1;

    // if odd_count {
    //     n.push_nibble_front(0);
    // }

    // n

    // let hashed_addr = hash(addr.as_bytes());
    // Nibbles::from_h256_be(hashed_addr)

    Nibbles::from_h256_be(hash(&addr.0))
}

// TODO: Extreme hack! Please don't keep...
fn string_to_nibbles_even_nibble_fixed(s: &str) -> Nibbles {
    let mut n = Nibbles::from_str(s).unwrap();
    let odd_count = (n.count & 1) == 1;

    if odd_count {
        n.push_nibble_front(0);
    }

    n
}
