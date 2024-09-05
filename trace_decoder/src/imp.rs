use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    mem,
    ops::Range,
};

use alloy_compat::Compat as _;
use anyhow::{anyhow, ensure, Context as _};
use ethereum_types::{Address, U256};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, TrieInputs},
    proof::TrieRoots,
    testing_utils::{BEACON_ROOTS_CONTRACT_ADDRESS, HISTORY_BUFFER_LENGTH_VALUE},
    GenerationInputs,
};
use itertools::Itertools as _;
use keccak_hash::H256;
use mpt_trie::partial_trie::PartialTrie as _;
use nunny::NonEmpty;

use crate::{
    decoding::eth_to_gwei,
    processed_block_trace::{map_receipt_bytes, Hash2Code},
    typed_mpt::{ReceiptTrie, StateMpt, StateTrie, StorageTrie, TransactionTrie, TrieKey},
    BlockLevelData, BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    OtherBlockData, SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages,
    TxnInfo, TxnMeta, TxnTrace,
};

/// TODO(0xaatif): doc
pub fn entrypoint(
    trace: BlockTrace,
    other: OtherBlockData,
    batch_size: usize,
    use_burn_addr: bool,
) -> anyhow::Result<Vec<GenerationInputs>> {
    ensure!(batch_size != 0);

    let BlockTrace {
        trie_pre_images,
        code_db,
        txn_info,
    } = trace;
    let (state, storage, mut code) = start(trie_pre_images)?;
    code.extend(code_db);

    let OtherBlockData {
        b_data:
            BlockLevelData {
                b_meta,
                b_hashes,
                mut withdrawals,
            },
        checkpoint_state_trie_root,
    } = other;

    // TODO(0xaatif): docs for the RPC field say this is gwei already...
    //                in any case, this shouldn't be our problem.
    for (_, amt) in &mut withdrawals {
        *amt = eth_to_gwei(*amt)
    }

    let batches = middle(
        state,
        storage,
        batch(txn_info, batch_size),
        &mut code,
        b_meta.block_timestamp,
        b_meta.parent_beacon_block_root,
        withdrawals,
    )?;

    let mut running_gas_used = 0;
    Ok(batches
        .into_iter()
        .map(
            |Batch {
                 first_txn_ix,
                 gas_used,
                 contract_code,
                 byte_code,
                 before:
                     IntraBlockTries {
                         state,
                         storage,
                         transaction,
                         receipt,
                     },
                 after,
                 withdrawals,
             }| GenerationInputs {
                txn_number_before: first_txn_ix.into(),
                gas_used_before: running_gas_used.into(),
                gas_used_after: {
                    running_gas_used += gas_used;
                    running_gas_used.into()
                },
                signed_txns: byte_code.into_iter().map(Into::into).collect(),
                withdrawals,
                global_exit_roots: vec![],
                tries: TrieInputs {
                    state_trie: state.into(),
                    transactions_trie: transaction.into(),
                    receipts_trie: receipt.into(),
                    storage_tries: storage.into_iter().map(|(k, v)| (k, v.into())).collect(),
                },
                trie_roots_after: after,
                checkpoint_state_trie_root,
                contract_code: contract_code
                    .into_iter()
                    .map(|it| (keccak_hash::keccak(&it), it))
                    .collect(),
                block_metadata: b_meta.clone(),
                block_hashes: b_hashes.clone(),
                burn_addr: use_burn_addr.then_some(Address::zero()),
            },
        )
        .collect())
}

fn start(
    pre_images: BlockTraceTriePreImages,
) -> anyhow::Result<(StateMpt, BTreeMap<H256, StorageTrie>, Hash2Code)> {
    Ok(match pre_images {
        // TODO(0xaatif): refactor our convoluted input types
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => {
            let state = state.items().try_fold(
                StateMpt::default(),
                |mut acc, (nibbles, hash_or_val)| {
                    let path = TrieKey::from_nibbles(nibbles);
                    match hash_or_val {
                        mpt_trie::trie_ops::ValOrHash::Val(bytes) => {
                            #[expect(deprecated)] // this is MPT specific
                            acc.insert_by_hashed_address(
                                path.into_hash()
                                    .context("invalid path length in direct state trie")?,
                                rlp::decode(&bytes)
                                    .context("invalid AccountRlp in direct state trie")?,
                            )?;
                        }
                        mpt_trie::trie_ops::ValOrHash::Hash(h) => {
                            acc.insert_hash_by_key(path, h)?;
                        }
                    };
                    anyhow::Ok(acc)
                },
            )?;
            let storage = storage
                .into_iter()
                .map(|(k, SeparateTriePreImage::Direct(v))| {
                    v.items()
                        .try_fold(StorageTrie::default(), |mut acc, (nibbles, hash_or_val)| {
                            let path = TrieKey::from_nibbles(nibbles);
                            match hash_or_val {
                                mpt_trie::trie_ops::ValOrHash::Val(value) => {
                                    acc.insert(path, value)?;
                                }
                                mpt_trie::trie_ops::ValOrHash::Hash(h) => {
                                    acc.insert_hash(path, h)?;
                                }
                            };
                            anyhow::Ok(acc)
                        })
                        .map(|v| (k, v))
                })
                .collect::<Result<_, _>>()?;
            (state, storage, Hash2Code::new())
        }
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions = crate::wire::parse(&compact)
                .context("couldn't parse instructions from binary format")?;
            let crate::type1::Frontend {
                state,
                storage,
                code,
            } = crate::type1::frontend(instructions)?;
            (state, storage, code.into_iter().map(Into::into).collect())
        }
    })
}

/// Break `txns` into batches of length `hint`, prioritising creating at least
/// two batches.
///
/// [`None`] represents a dummy transaction.
fn batch(txns: Vec<TxnInfo>, hint: usize) -> Vec<Vec<Option<TxnInfo>>> {
    let mut txns = txns.into_iter().map(Some).collect::<Vec<_>>();
    let hint = cmp::max(hint, 1);
    let n_batches = txns.iter().chunks(hint).into_iter().count();
    match (txns.len(), n_batches) {
        // enough
        (_, 2..) => txns
            .into_iter()
            .chunks(hint)
            .into_iter()
            .map(FromIterator::from_iter)
            .collect(),
        // not enough batches at `hint`, but enough real transactions
        (2.., ..2) => {
            let second = txns.split_off(txns.len() / 2);
            vec![txns, second]
        }
        // add padding
        (0 | 1, _) => txns
            .into_iter()
            .pad_using(2, |_ix| None)
            .map(|it| vec![it])
            .collect(),
    }
}

#[test]
fn test_batch() {
    #[track_caller]
    fn do_test(n: usize, hint: usize, exp: impl IntoIterator<Item = usize>) {
        itertools::assert_equal(
            exp,
            batch(vec![TxnInfo::default(); n], hint)
                .iter()
                .map(Vec::len),
        )
    }

    do_test(0, 0, [1, 1]); // pad2
    do_test(1, 0, [1, 1]); // pad1
    do_test(2, 0, [1, 1]); // exact
    do_test(3, 0, [1, 1, 1]);
    do_test(3, 1, [1, 1, 1]);
    do_test(3, 2, [2, 1]); // leftover after hint
    do_test(3, 3, [1, 2]); // big hint
}

#[derive(Debug)]
struct Batch<StateTrieT> {
    pub first_txn_ix: usize,
    pub gas_used: u64,
    /// See [`GenerationInputs::contract_code`].
    pub contract_code: BTreeSet<Vec<u8>>,
    /// For each transaction in batch, in order.
    pub byte_code: Vec<NonEmpty<Vec<u8>>>,

    pub before: IntraBlockTries<StateTrieT>,
    pub after: TrieRoots,

    /// Empty for all but the final batch
    pub withdrawals: Vec<(Address, U256)>,
}

/// [`evm_arithmetization::generation::TrieInputs`],
/// generic over state trie representation.
#[derive(Debug)]
struct IntraBlockTries<StateTrieT> {
    pub state: StateTrieT,
    pub storage: BTreeMap<H256, StorageTrie>,
    pub transaction: TransactionTrie,
    pub receipt: ReceiptTrie,
}

fn middle<StateTrieT: StateTrie + Clone>(
    // state at the beginning of the block
    mut state_trie: StateTrieT,
    // storage at the beginning of the block
    mut storage: BTreeMap<H256, StorageTrie>,
    // None represents a dummy txn
    // All vecs must be non-empty.
    batches: Vec<Vec<Option<TxnInfo>>>,
    code: &mut Hash2Code,
    block_timestamp: U256,
    parent_beacon_block_root: H256,
    mut withdrawals: Vec<(Address, U256)>,
) -> anyhow::Result<Vec<Batch<StateTrieT>>> {
    // Initialise the storage tries.
    for (haddr, acct) in state_trie.iter() {
        let storage = storage.entry(haddr).or_insert({
            let mut it = StorageTrie::default();
            it.insert_hash(TrieKey::default(), acct.storage_root)
                .expect("empty trie insert cannot fail");
            it
        });
        ensure!(
            storage.root() == acct.storage_root,
            "inconsistent initial storage for hashed address {haddr:x}"
        )
    }

    // These are the per-block tries.
    let mut transaction_trie = TransactionTrie::new();
    let mut receipt_trie = ReceiptTrie::new();

    let mut out = vec![];

    let mut curr_txn_ix = 0;
    let len_txns = batches.iter().flatten().count();

    for batch in batches {
        let batch_first_txn_ix = curr_txn_ix; // GOTCHA: if there are no transactions in this batch
        let mut batch_gas_used = 0;
        let mut batch_byte_code = vec![];
        let mut batch_contract_code = BTreeSet::from([vec![]]); // always include empty code

        let mut before = IntraBlockTries {
            state: state_trie.clone(),
            transaction: transaction_trie.clone(),
            receipt: receipt_trie.clone(),
            storage: storage.clone(),
        };
        // We want to trim the TrieInputs above,
        // but won't know the bounds until after the loop below,
        // so store that information here.
        let mut storage_masks = BTreeMap::<_, BTreeSet<TrieKey>>::new();
        let mut state_mask = BTreeSet::new();

        if curr_txn_ix == 0 && batch[0].is_some() {
            cancun_hook(
                block_timestamp,
                &mut storage,
                &mut storage_masks,
                parent_beacon_block_root,
                &mut state_mask,
                &mut state_trie,
            )?;
        }

        for TxnInfo {
            traces,
            meta:
                TxnMeta {
                    byte_code: txn_byte_code,
                    new_receipt_trie_node_byte,
                    gas_used: txn_gas_used,
                },
        } in batch.into_iter().flatten()
        {
            if let Ok(nonempty) = nunny::Vec::new(txn_byte_code) {
                batch_byte_code.push(nonempty.clone());
                transaction_trie.insert(curr_txn_ix, nonempty.into())?;
                receipt_trie.insert(
                    curr_txn_ix,
                    map_receipt_bytes(new_receipt_trie_node_byte.clone())?,
                )?;
            }

            batch_gas_used += txn_gas_used;

            for (
                addr,
                empty,
                TxnTrace {
                    balance,
                    nonce,
                    storage_read,
                    storage_written,
                    code_usage,
                    self_destructed,
                },
            ) in traces
                .into_iter()
                .map(|(addr, trc)| (addr, trc == TxnTrace::default(), trc))
            {
                let (mut acct, born) = state_trie
                    .get_by_address(addr)
                    .map(|acct| (acct, false))
                    .unwrap_or((AccountRlp::default(), true));

                let commit = match born {
                    false => !empty,
                    true => {
                        let (_, _, receipt) = evm_arithmetization::generation::mpt::decode_receipt(
                            &map_receipt_bytes(new_receipt_trie_node_byte.clone())?,
                        )
                        .map_err(|e| anyhow!("{e:?}"))
                        .context("couldn't decode receipt")?;
                        receipt.status && !empty
                    } // if txn failed, don't commit changes to trie
                };

                let storage_mask = storage_masks.entry(addr).or_default();

                storage_mask.extend(
                    storage_written
                        .keys()
                        .chain(&storage_read)
                        .map(|it| TrieKey::from_hash(keccak_hash::keccak(it))),
                );

                if commit {
                    acct.balance = balance.unwrap_or(acct.balance);
                    acct.nonce = nonce.unwrap_or(acct.nonce);
                    acct.code_hash = code_usage
                        .map(|it| match it {
                            ContractCodeUsage::Read(hash) => {
                                batch_contract_code.insert(code.get(hash)?);
                                anyhow::Ok(hash)
                            }
                            ContractCodeUsage::Write(bytes) => {
                                code.insert(bytes.clone());
                                let hash = keccak_hash::keccak(&bytes);
                                batch_contract_code.insert(bytes);
                                Ok(hash)
                            }
                        })
                        .transpose()?
                        .unwrap_or(acct.code_hash);

                    if !storage_written.is_empty() {
                        let storage = match born {
                            true => storage.entry(keccak_hash::keccak(addr)).or_default(),
                            false => storage
                                .get_mut(&keccak_hash::keccak(addr))
                                .context(format!("missing storage trie for address {addr:x}"))?,
                        };

                        for (k, v) in storage_written {
                            let slot = TrieKey::from_hash(keccak_hash::keccak(k));
                            match v.is_zero() {
                                // this is actually a delete
                                true => storage_mask.extend(storage.reporting_remove(slot)?),
                                false => {
                                    storage.insert(slot, rlp::encode(&v).to_vec())?;
                                }
                            }
                        }
                        acct.storage_root = storage.root();
                    }

                    state_trie.insert_by_address(addr, acct)?;
                }

                if self_destructed {
                    storage.remove(&keccak_hash::keccak(addr));
                    state_mask.extend(state_trie.reporting_remove(addr)?)
                }

                let is_precompile =
                    PRECOMPILE_ADDRESS_RANGE.contains(&U256::from_big_endian(addr.as_bytes()));

                // Trie witnesses will only include accessed precompile accounts as hash
                // nodes if the transaction calling them reverted. If this is the case, we
                // shouldn't include them in this transaction's `state_accesses` to allow the
                // decoder to build a minimal state trie without hitting any hash node.

                if !is_precompile || state_trie.get_by_address(addr).is_some() {
                    state_mask.insert(TrieKey::from_address(addr));
                }
            }

            curr_txn_ix += 1;
        } // txn in batch

        out.push(Batch {
            first_txn_ix: batch_first_txn_ix,
            gas_used: batch_gas_used,
            contract_code: batch_contract_code,
            byte_code: batch_byte_code,
            withdrawals: match curr_txn_ix == len_txns {
                true => {
                    for (addr, amt) in &withdrawals {
                        state_mask.insert(TrieKey::from_address(*addr));
                        let mut acct = state_trie
                            .get_by_address(*addr)
                            .context("missing address for withdrawal")?;
                        acct.balance += *amt;
                        state_trie
                            .insert_by_address(*addr, acct)
                            // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
                            //                Add an entry API
                            .expect("insert must succeed with the same key as a successful `get`");
                    }
                    mem::take(&mut withdrawals)
                }
                false => vec![],
            },
            before: {
                before.state.mask(state_mask)?;
                before.receipt.mask(batch_first_txn_ix..curr_txn_ix)?;
                before.transaction.mask(batch_first_txn_ix..curr_txn_ix)?;

                let keep = storage_masks
                    .keys()
                    .map(keccak_hash::keccak)
                    .collect::<BTreeSet<_>>();
                before.storage.retain(|haddr, _| keep.contains(haddr));

                for (addr, mask) in storage_masks {
                    if let Some(it) = before.storage.get_mut(&keccak_hash::keccak(addr)) {
                        it.mask(mask)?
                    } // TODO(0xaatif): why is this fallible?
                }
                before
            },
            after: TrieRoots {
                state_root: state_trie.root(),
                transactions_root: transaction_trie.root(),
                receipts_root: receipt_trie.root(),
            },
        });
    } // batch in batches

    Ok(out)
}

fn cancun_hook<StateTrieT: StateTrie + Clone>(
    block_timestamp: U256,
    storage: &mut BTreeMap<H256, StorageTrie>,
    storage_masks: &mut BTreeMap<ethereum_types::H160, BTreeSet<TrieKey>>,
    parent_beacon_block_root: H256,
    trim_state: &mut BTreeSet<TrieKey>,
    state_trie: &mut StateTrieT,
) -> anyhow::Result<()> {
    let history_buffer_length = U256::from(HISTORY_BUFFER_LENGTH_VALUE);
    let history_timestamp = block_timestamp % history_buffer_length;
    let history_timestamp_next = history_timestamp + history_buffer_length;
    let beacon_storage = storage
        .get_mut(&keccak_hash::keccak(BEACON_ROOTS_CONTRACT_ADDRESS))
        .context("missing beacon contract storage trie")?;
    let storage_mask = storage_masks
        .entry(BEACON_ROOTS_CONTRACT_ADDRESS)
        .or_default();
    for (ix, u) in [
        (history_timestamp, block_timestamp),
        (
            history_timestamp_next,
            U256::from_big_endian(parent_beacon_block_root.as_bytes()),
        ),
    ] {
        let mut h = [0; 32];
        ix.to_big_endian(&mut h);
        let slot = TrieKey::from_hash(keccak_hash::keccak(H256::from_slice(&h)));
        storage_mask.insert(slot);

        match u.is_zero() {
            true => storage_mask.extend(beacon_storage.reporting_remove(slot)?),
            false => {
                beacon_storage.insert(slot, alloy::rlp::encode(u.compat()))?;
                storage_mask.insert(slot);
            }
        }
    }
    trim_state.insert(TrieKey::from_address(BEACON_ROOTS_CONTRACT_ADDRESS));
    let mut beacon_acct = state_trie
        .get_by_address(BEACON_ROOTS_CONTRACT_ADDRESS)
        .context("missing beacon contract address")?;
    beacon_acct.storage_root = beacon_storage.root();
    state_trie
        .insert_by_address(BEACON_ROOTS_CONTRACT_ADDRESS, beacon_acct)
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
        //                Add an entry API
        .expect("insert must succeed with the same key as a successful `get`");
    Ok(())
}

// TODO(0xaatif): is this _meant_ to exclude the final member?
const PRECOMPILE_ADDRESS_RANGE: Range<U256> = U256([1, 0, 0, 0])..U256([10, 0, 0, 0]);
