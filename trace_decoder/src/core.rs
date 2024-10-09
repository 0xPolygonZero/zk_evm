use std::{
    cmp,
    collections::{BTreeMap, BTreeSet, HashMap},
    mem,
};

use anyhow::{anyhow, bail, ensure, Context as _};
use either::Either;
use ethereum_types::{Address, BigEndianHash as _, U256};
use evm_arithmetization::{
    generation::{mpt::AccountRlp, TrieInputs},
    proof::{BlockMetadata, TrieRoots},
    GenerationInputs,
};
use itertools::Itertools as _;
use keccak_hash::H256;
use mpt_trie::partial_trie::PartialTrie as _;
use nunny::NonEmpty;
use zk_evm_common::gwei_to_wei;

use crate::{
    observer::{DummyObserver, Observer},
    tries::Type2World,
};
use crate::{
    tries::{MptKey, ReceiptTrie, StorageTrie, TransactionTrie, Type1World, World},
    BlockLevelData, BlockTrace, BlockTraceTriePreImages, CombinedPreImages, ContractCodeUsage,
    OtherBlockData, SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages,
    TxnInfo, TxnMeta, TxnTrace,
};

/// Expected trie type when parsing from binary in a [`BlockTrace`].
///
/// See [`crate::wire`] and [`CombinedPreImages`] for more.
#[derive(Debug)]
pub enum WireDisposition {
    /// MPT
    Type1,
    /// SMT
    Type2,
}

/// TODO(0xaatif): document this after <https://github.com/0xPolygonZero/zk_evm/issues/275>
pub fn entrypoint(
    trace: BlockTrace,
    other: OtherBlockData,
    batch_size_hint: usize,
    observer: &mut impl Observer<Type1World>,
    wire_disposition: WireDisposition,
) -> anyhow::Result<Vec<GenerationInputs>> {
    ensure!(batch_size_hint != 0);

    let BlockTrace {
        trie_pre_images,
        code_db,
        txn_info,
    } = trace;

    let fatal_missing_code = match trie_pre_images {
        BlockTraceTriePreImages::Separate(_) => FatalMissingCode(true),
        BlockTraceTriePreImages::Combined(_) => FatalMissingCode(false),
    };
    let (state, storage, mut code) = start(trie_pre_images, wire_disposition)?;

    code.extend(code_db);

    let OtherBlockData {
        b_data:
            BlockLevelData {
                b_meta,
                b_hashes,
                mut withdrawals,
            },
        checkpoint_state_trie_root,
        checkpoint_consolidated_hash,
        burn_addr,
        ger_data,
    } = other;

    for (_, amt) in &mut withdrawals {
        *amt = gwei_to_wei(*amt)
    }

    let batches = match state {
        Either::Left(mpt) => Either::Left(
            middle(
                mpt,
                storage,
                batch(txn_info, batch_size_hint),
                &mut code,
                &b_meta,
                ger_data,
                withdrawals,
                fatal_missing_code,
                observer,
            )?
            .into_iter()
            .map(|it| it.map(Either::Left)),
        ),
        Either::Right(smt) => {
            Either::Right(
                middle(
                    smt,
                    storage,
                    batch(txn_info, batch_size_hint),
                    &mut code,
                    &b_meta,
                    ger_data,
                    withdrawals,
                    fatal_missing_code,
                    &mut DummyObserver::new(), // TODO(0xaatif)
                )?
                .into_iter()
                .map(|it| it.map(Either::Right)),
            )
        }
    };

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
                ger_data,
                tries: TrieInputs {
                    state_trie: match state {
                        Either::Left(mpt) => mpt.into(),
                        Either::Right(_) => todo!("evm_arithmetization accepts an SMT"),
                    },
                    transactions_trie: transaction.into(),
                    receipts_trie: receipt.into(),
                    storage_tries: storage.into_iter().map(|(k, v)| (k, v.into())).collect(),
                },
                trie_roots_after: after,
                checkpoint_state_trie_root,
                checkpoint_consolidated_hash,
                contract_code: contract_code
                    .into_iter()
                    .map(|it| (keccak_hash::keccak(&it), it))
                    .collect(),
                block_metadata: b_meta.clone(),
                block_hashes: b_hashes.clone(),
                burn_addr,
            },
        )
        .collect())
}

/// The user has either provided us with a [`serde`]-ed
/// [`HashedPartialTrie`](mpt_trie::partial_trie::HashedPartialTrie),
/// or a [`wire`](crate::wire)-encoded representation of one.
///
/// Turn either of those into our [internal representations](crate::tries).
#[allow(clippy::type_complexity)]
fn start(
    pre_images: BlockTraceTriePreImages,
    wire_disposition: WireDisposition,
) -> anyhow::Result<(
    Either<Type1World, Type2World>,
    BTreeMap<H256, StorageTrie>,
    Hash2Code,
)> {
    Ok(match pre_images {
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/401
        //                refactor our convoluted input types
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => {
            let state = state.items().try_fold(
                Type1World::default(),
                |mut acc, (nibbles, hash_or_val)| {
                    let path = MptKey::from_nibbles(nibbles);
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
                            let path = MptKey::from_nibbles(nibbles);
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
            (Either::Left(state), storage, Hash2Code::new())
        }
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions = crate::wire::parse(&compact)
                .context("couldn't parse instructions from binary format")?;
            let (state, storage, code) = match wire_disposition {
                WireDisposition::Type1 => {
                    let crate::type1::Frontend {
                        state,
                        storage,
                        code,
                    } = crate::type1::frontend(instructions)?;
                    (
                        Either::Left(state),
                        storage,
                        Hash2Code::from_iter(code.into_iter().map(NonEmpty::into_vec)),
                    )
                }
                WireDisposition::Type2 => {
                    let crate::type2::Frontend { trie, code } =
                        crate::type2::frontend(instructions)?;
                    (
                        Either::Right(trie),
                        BTreeMap::new(),
                        Hash2Code::from_iter(code.into_iter().map(NonEmpty::into_vec)),
                    )
                }
            };
            (state, storage, code)
        }
    })
}

/// Break `txns` into batches of length `batch_size_hint`, prioritising creating
/// at least two batches.
///
/// [`None`] represents a dummy transaction that should not increment the
/// transaction index.
fn batch(txns: Vec<TxnInfo>, batch_size_hint: usize) -> Vec<Vec<Option<TxnInfo>>> {
    let hint = cmp::max(batch_size_hint, 1);
    let mut txns = txns.into_iter().map(Some).collect::<Vec<_>>();
    let n_batches = txns.iter().chunks(hint).into_iter().count();
    match (txns.len(), n_batches) {
        // enough
        (_, 2..) => txns
            .into_iter()
            .chunks(hint)
            .into_iter()
            .map(FromIterator::from_iter)
            .collect(),
        // not enough batches at `hint`, but enough real transactions,
        // so just split them in half
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

impl<T> Batch<T> {
    fn map<U>(self, f: impl FnMut(T) -> U) -> Batch<U> {
        let Self {
            first_txn_ix,
            gas_used,
            contract_code,
            byte_code,
            before,
            after,
            withdrawals,
        } = self;
        Batch {
            first_txn_ix,
            gas_used,
            contract_code,
            byte_code,
            before: before.map(f),
            after,
            withdrawals,
        }
    }
}

/// [`evm_arithmetization::generation::TrieInputs`],
/// generic over state trie representation.
#[derive(Debug)]
pub struct IntraBlockTries<StateTrieT> {
    pub state: StateTrieT,
    pub storage: BTreeMap<H256, StorageTrie>,
    pub transaction: TransactionTrie,
    pub receipt: ReceiptTrie,
}

impl<T> IntraBlockTries<T> {
    fn map<U>(self, mut f: impl FnMut(T) -> U) -> IntraBlockTries<U> {
        let Self {
            state,
            storage,
            transaction,
            receipt,
        } = self;
        IntraBlockTries {
            state: f(state),
            storage,
            transaction,
            receipt,
        }
    }
}
/// Hacky handling of possibly missing contract bytecode in `Hash2Code` inner
/// map.
/// Allows incomplete payloads fetched with the zero tracer to skip these
/// silently.
// TODO(Nashtare): https://github.com/0xPolygonZero/zk_evm/issues/700
#[derive(Copy, Clone)]
pub struct FatalMissingCode(pub bool);

/// Does the main work mentioned in the [module documentation](super).
#[allow(clippy::too_many_arguments)]
fn middle<StateTrieT: World<AccountInfo = AccountRlp> + Clone>(
    // state at the beginning of the block
    mut state_trie: StateTrieT,
    // storage at the beginning of the block
    mut storage_tries: BTreeMap<H256, StorageTrie>,
    // None represents a dummy transaction that should not increment the transaction index
    // all batches SHOULD not be empty
    batches: Vec<Vec<Option<TxnInfo>>>,
    code: &mut Hash2Code,
    block: &BlockMetadata,
    ger_data: Option<(H256, H256)>,
    // added to final batch
    mut withdrawals: Vec<(Address, U256)>,
    fatal_missing_code: FatalMissingCode,
    // called with the untrimmed tries after each batch
    observer: &mut impl Observer<StateTrieT>,
) -> anyhow::Result<Vec<Batch<StateTrieT>>>
where
    StateTrieT::StateKey: Ord + From<Address>,
{
    // Initialise the storage tries.
    for (haddr, acct) in state_trie.iter_account_info() {
        let storage = storage_tries.entry(haddr).or_insert({
            let mut it = StorageTrie::default();
            it.insert_hash(MptKey::default(), acct.storage_root)
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

    let mut txn_ix = 0; // incremented for non-dummy transactions
    let mut loop_ix = 0; // always incremented
    let loop_len = batches.iter().flatten().count();
    for (batch_index, batch) in batches.into_iter().enumerate() {
        let batch_first_txn_ix = txn_ix; // GOTCHA: if there are no transactions in this batch
        let mut batch_gas_used = 0;
        let mut batch_byte_code = vec![];
        let mut batch_contract_code = BTreeSet::from([vec![]]); // always include empty code

        let mut before = IntraBlockTries {
            state: state_trie.clone(),
            transaction: transaction_trie.clone(),
            receipt: receipt_trie.clone(),
            storage: storage_tries.clone(),
        };

        // We want to perform mask the TrieInputs above,
        // but won't know the bounds until after the loop below,
        // so store that information here.
        let mut storage_masks = BTreeMap::<_, BTreeSet<MptKey>>::new();
        let mut state_mask = BTreeSet::<StateTrieT::StateKey>::new();

        if txn_ix == 0 {
            do_pre_execution(
                block,
                ger_data,
                &mut storage_tries,
                &mut storage_masks,
                &mut state_mask,
                &mut state_trie,
            )?;
        }

        for txn in batch {
            let do_increment_txn_ix = txn.is_some();
            let TxnInfo {
                traces,
                meta:
                    TxnMeta {
                        byte_code,
                        new_receipt_trie_node_byte,
                        gas_used: txn_gas_used,
                    },
            } = txn.unwrap_or_default();

            let tx_hash = keccak_hash::keccak(&byte_code);

            if let Ok(nonempty) = nunny::Vec::new(byte_code) {
                batch_byte_code.push(nonempty.clone());
                transaction_trie.insert(txn_ix, nonempty.into())?;
                receipt_trie.insert(
                    txn_ix,
                    map_receipt_bytes(new_receipt_trie_node_byte.clone())?,
                )?;
            }

            batch_gas_used += txn_gas_used;

            for (
                addr,
                just_access,
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
                let (_, _, receipt) = evm_arithmetization::generation::mpt::decode_receipt(
                    &map_receipt_bytes(new_receipt_trie_node_byte.clone())?,
                )
                .map_err(|e| anyhow!("{e:?}"))
                .context(format!("couldn't decode receipt in txn {tx_hash:x}"))?;

                let (mut acct, born) = state_trie
                    .get_account_info(addr)
                    .map(|acct| (acct, false))
                    .unwrap_or((AccountRlp::default(), true));

                if born {
                    // Empty accounts cannot have non-empty storage,
                    // so we can safely insert a default trie.
                    storage_tries.insert(keccak_hash::keccak(addr), StorageTrie::default());
                }

                if born || just_access {
                    state_trie
                        .clone()
                        .insert_account_info(addr, acct)
                        .context(format!(
                            "couldn't reach state of {} address {addr:x} in txn {tx_hash:x}",
                            match born {
                                true => "created",
                                false => "accessed",
                            }
                        ))?;
                }

                let do_writes = !just_access
                    && match born {
                        // if txn failed, don't commit changes to trie
                        true => receipt.status,
                        false => true,
                    };

                let storage_mask = storage_masks.entry(addr).or_default();

                storage_mask.extend(
                    storage_written
                        .keys()
                        .chain(&storage_read)
                        .map(|it| MptKey::from_hash(keccak_hash::keccak(it))),
                );

                if do_writes {
                    acct.balance = balance.unwrap_or(acct.balance);
                    acct.nonce = nonce.unwrap_or(acct.nonce);
                    acct.code_hash = code_usage
                        .map(|it| match it {
                            ContractCodeUsage::Read(hash) => {
                                // TODO(Nashtare): https://github.com/0xPolygonZero/zk_evm/issues/700
                                // This is a bug in the zero tracer, which shouldn't be giving us
                                // this read at all. Workaround for now.
                                match (fatal_missing_code, code.get(hash)) {
                                    (FatalMissingCode(true), None) => {
                                        bail!("no code for hash {hash:x}")
                                    }
                                    (_, Some(byte_code)) => {
                                        batch_contract_code.insert(byte_code);
                                    }
                                    (_, None) => {
                                        log::warn!("no code for {hash:x}")
                                    }
                                }

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
                            true => storage_tries.entry(keccak_hash::keccak(addr)).or_default(),
                            false => storage_tries.get_mut(&keccak_hash::keccak(addr)).context(
                                format!(
                                    "missing storage trie for address {addr:x} in txn {tx_hash:x}"
                                ),
                            )?,
                        };

                        for (k, v) in storage_written {
                            match v.is_zero() {
                                // this is actually a delete
                                true => {
                                    storage_mask.extend(storage.reporting_remove(
                                        MptKey::from_hash(keccak_hash::keccak(k)),
                                    )?)
                                }
                                false => {
                                    storage.store_int_at_slot(k.into_uint(), v)?;
                                }
                            }
                        }
                        acct.storage_root = storage.root();
                    }

                    state_trie.insert_account_info(addr, acct)?;
                    state_mask.insert(<StateTrieT::StateKey>::from(addr));
                } else {
                    // Simple state access
                    state_mask.insert(<StateTrieT::StateKey>::from(addr));
                }

                if self_destructed {
                    storage_tries.remove(&keccak_hash::keccak(addr));
                    state_mask.extend(state_trie.reporting_remove(addr)?)
                }
            }

            if do_increment_txn_ix {
                txn_ix += 1;
            }
            loop_ix += 1;
        } // txn in batch

        out.push(Batch {
            first_txn_ix: batch_first_txn_ix,
            gas_used: batch_gas_used,
            contract_code: batch_contract_code,
            byte_code: batch_byte_code,
            withdrawals: match loop_ix == loop_len {
                true => {
                    for (addr, amt) in &withdrawals {
                        state_mask.insert(<StateTrieT::StateKey>::from(*addr));
                        let mut acct = state_trie
                            .get_account_info(*addr)
                            .context(format!("missing address {addr:x} for withdrawal"))?;
                        acct.balance += *amt;
                        state_trie
                            .insert_account_info(*addr, acct)
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
                before.receipt.mask(batch_first_txn_ix..txn_ix)?;
                before.transaction.mask(batch_first_txn_ix..txn_ix)?;

                let keep = storage_masks
                    .keys()
                    .map(keccak_hash::keccak)
                    .collect::<BTreeSet<_>>();
                before.storage.retain(|haddr, _| keep.contains(haddr));

                for (addr, mask) in storage_masks {
                    if let Some(it) = before.storage.get_mut(&keccak_hash::keccak(addr)) {
                        it.mask(mask)?
                    } // else must have self-destructed
                }
                before
            },
            after: TrieRoots {
                state_root: state_trie.root(),
                transactions_root: transaction_trie.root(),
                receipts_root: receipt_trie.root(),
            },
        });

        observer.collect_tries(
            block.block_number,
            batch_index,
            &state_trie,
            &storage_tries,
            &transaction_trie,
            &receipt_trie,
        )
    } // batch in batches

    Ok(out)
}

/// Performs all the pre-txn execution rules of the targeted network.
fn do_pre_execution<StateTrieT: World<AccountInfo = AccountRlp> + Clone>(
    block: &BlockMetadata,
    ger_data: Option<(H256, H256)>,
    storage: &mut BTreeMap<H256, StorageTrie>,
    trim_storage: &mut BTreeMap<ethereum_types::H160, BTreeSet<MptKey>>,
    trim_state: &mut BTreeSet<StateTrieT::StateKey>,
    state_trie: &mut StateTrieT,
) -> anyhow::Result<()>
where
    StateTrieT::StateKey: From<Address> + Ord,
{
    // Ethereum mainnet: EIP-4788
    if cfg!(feature = "eth_mainnet") {
        return do_beacon_hook(
            block.block_timestamp,
            storage,
            trim_storage,
            block.parent_beacon_block_root,
            trim_state,
            state_trie,
        );
    }

    if cfg!(feature = "cdk_erigon") {
        return do_scalable_hook(
            block,
            ger_data,
            storage,
            trim_storage,
            trim_state,
            state_trie,
        );
    }

    Ok(())
}

/// Updates the storage of the Scalable and GER contracts, according to
/// <https://docs.polygon.technology/zkEVM/architecture/proving-system/processing-l2-blocks/#etrog-upgrade-fork-id-6>.
///
/// This is Polygon-CDK-specific, and runs at the start of the block,
/// before any transactions (as per the Etrog specification).
fn do_scalable_hook<StateTrieT: World<AccountInfo = AccountRlp> + Clone>(
    block: &BlockMetadata,
    ger_data: Option<(H256, H256)>,
    storage: &mut BTreeMap<H256, StorageTrie>,
    trim_storage: &mut BTreeMap<ethereum_types::H160, BTreeSet<MptKey>>,
    trim_state: &mut BTreeSet<StateTrieT::StateKey>,
    state_trie: &mut StateTrieT,
) -> anyhow::Result<()>
where
    StateTrieT::StateKey: From<Address> + Ord,
{
    use evm_arithmetization::testing_utils::{
        ADDRESS_SCALABLE_L2, ADDRESS_SCALABLE_L2_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_ADDRESS,
        GLOBAL_EXIT_ROOT_ADDRESS_HASHED, GLOBAL_EXIT_ROOT_STORAGE_POS, LAST_BLOCK_STORAGE_POS,
        STATE_ROOT_STORAGE_POS, TIMESTAMP_STORAGE_POS,
    };

    if block.block_number.is_zero() {
        return Err(anyhow!("Attempted to prove the Genesis block!"));
    }
    let scalable_storage = storage
        .get_mut(&ADDRESS_SCALABLE_L2_ADDRESS_HASHED)
        .context("missing scalable contract storage trie")?;
    let scalable_trim = trim_storage.entry(ADDRESS_SCALABLE_L2).or_default();

    let timestamp_slot_key = MptKey::from_slot_position(U256::from(TIMESTAMP_STORAGE_POS.1));

    let timestamp = scalable_storage
        .load_int(timestamp_slot_key)
        .unwrap_or_default();
    let timestamp = core::cmp::max(timestamp, block.block_timestamp);

    // Store block number and largest timestamp

    for (ix, u) in [
        (U256::from(LAST_BLOCK_STORAGE_POS.1), block.block_number),
        (U256::from(TIMESTAMP_STORAGE_POS.1), timestamp),
    ] {
        ensure!(u != U256::zero());
        scalable_storage.store_int_at_slot(ix, u)?;
        scalable_trim.insert(MptKey::from_slot_position(ix));
    }

    // Store previous block root hash

    let prev_block_root_hash = state_trie.root();
    let mut arr = [0; 64];
    (block.block_number - 1).to_big_endian(&mut arr[0..32]);
    U256::from(STATE_ROOT_STORAGE_POS.1).to_big_endian(&mut arr[32..64]);
    let slot = MptKey::from_hash(keccak_hash::keccak(arr));

    scalable_storage.store_hash(slot, prev_block_root_hash)?;
    scalable_trim.insert(slot);

    trim_state.insert(<StateTrieT::StateKey>::from(ADDRESS_SCALABLE_L2));
    let mut scalable_acct = state_trie
        .get_account_info(ADDRESS_SCALABLE_L2)
        .context("missing scalable contract address")?;
    scalable_acct.storage_root = scalable_storage.root();
    state_trie
        .insert_account_info(ADDRESS_SCALABLE_L2, scalable_acct)
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
        //                Add an entry API
        .expect("insert must succeed with the same key as a successful `get`");

    // Update GER contract's storage if necessary
    if let Some((root, l1blockhash)) = ger_data {
        let ger_storage = storage
            .get_mut(&GLOBAL_EXIT_ROOT_ADDRESS_HASHED)
            .context("missing GER contract storage trie")?;
        let ger_trim = trim_storage.entry(GLOBAL_EXIT_ROOT_ADDRESS).or_default();

        let mut arr = [0; 64];
        arr[0..32].copy_from_slice(&root.0);
        U256::from(GLOBAL_EXIT_ROOT_STORAGE_POS.1).to_big_endian(&mut arr[32..64]);
        let slot = MptKey::from_hash(keccak_hash::keccak(arr));

        ger_storage.store_hash(slot, l1blockhash)?;
        ger_trim.insert(slot);

        trim_state.insert(<StateTrieT::StateKey>::from(GLOBAL_EXIT_ROOT_ADDRESS));
        let mut ger_acct = state_trie
            .get_account_info(GLOBAL_EXIT_ROOT_ADDRESS)
            .context("missing GER contract address")?;
        ger_acct.storage_root = ger_storage.root();
        state_trie
            .insert_account_info(GLOBAL_EXIT_ROOT_ADDRESS, ger_acct)
            // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
            //                Add an entry API
            .expect("insert must succeed with the same key as a successful `get`");
    }

    Ok(())
}

/// Updates the storage of the beacon block root contract,
/// according to <https://eips.ethereum.org/EIPS/eip-4788>
///
/// This is Cancun-specific, and runs at the start of the block,
/// before any transactions (as per the EIP).
fn do_beacon_hook<StateTrieT: World<AccountInfo = AccountRlp> + Clone>(
    block_timestamp: U256,
    storage: &mut BTreeMap<H256, StorageTrie>,
    trim_storage: &mut BTreeMap<ethereum_types::H160, BTreeSet<MptKey>>,
    parent_beacon_block_root: H256,
    trim_state: &mut BTreeSet<StateTrieT::StateKey>,
    state_trie: &mut StateTrieT,
) -> anyhow::Result<()>
where
    StateTrieT::StateKey: From<Address> + Ord,
{
    use evm_arithmetization::testing_utils::{
        BEACON_ROOTS_CONTRACT_ADDRESS, BEACON_ROOTS_CONTRACT_ADDRESS_HASHED, HISTORY_BUFFER_LENGTH,
    };

    let timestamp_idx = block_timestamp % HISTORY_BUFFER_LENGTH.value;
    let root_idx = timestamp_idx + HISTORY_BUFFER_LENGTH.value;
    let beacon_storage = storage
        .get_mut(&BEACON_ROOTS_CONTRACT_ADDRESS_HASHED)
        .context("missing beacon contract storage trie")?;
    let beacon_trim = trim_storage
        .entry(BEACON_ROOTS_CONTRACT_ADDRESS)
        .or_default();

    for (ix, u) in [
        (timestamp_idx, block_timestamp),
        (
            root_idx,
            U256::from_big_endian(parent_beacon_block_root.as_bytes()),
        ),
    ] {
        let slot = MptKey::from_slot_position(ix);

        match u.is_zero() {
            true => beacon_trim.extend(beacon_storage.reporting_remove(slot)?),
            false => {
                beacon_storage.store_int_at_slot(ix, u)?;
                beacon_trim.insert(slot);
            }
        }
    }
    trim_state.insert(<StateTrieT::StateKey>::from(BEACON_ROOTS_CONTRACT_ADDRESS));
    let mut beacon_acct = state_trie
        .get_account_info(BEACON_ROOTS_CONTRACT_ADDRESS)
        .context("missing beacon contract address")?;
    beacon_acct.storage_root = beacon_storage.root();
    state_trie
        .insert_account_info(BEACON_ROOTS_CONTRACT_ADDRESS, beacon_acct)
        // TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
        //                Add an entry API
        .expect("insert must succeed with the same key as a successful `get`");
    Ok(())
}

fn map_receipt_bytes(bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    match rlp::decode::<evm_arithmetization::generation::mpt::LegacyReceiptRlp>(&bytes) {
        Ok(_) => Ok(bytes),
        Err(_) => {
            rlp::decode(&bytes).context("couldn't decode receipt as a legacy receipt or raw bytes")
        }
    }
}

/// Code hash mappings that we have constructed from parsing the block
/// trace.
/// If there are any txns that create contracts, then they will also
/// get added here as we process the deltas.
struct Hash2Code {
    /// Key must always be [`hash`](keccak_hash) of value.
    inner: HashMap<H256, Vec<u8>>,
}

impl Hash2Code {
    pub fn new() -> Self {
        let mut this = Self {
            inner: HashMap::new(),
        };
        this.insert(vec![]);
        this
    }
    pub fn get(&mut self, hash: H256) -> Option<Vec<u8>> {
        self.inner.get(&hash).cloned()
    }
    pub fn insert(&mut self, code: Vec<u8>) {
        self.inner.insert(keccak_hash::keccak(&code), code);
    }
}

impl Extend<Vec<u8>> for Hash2Code {
    fn extend<II: IntoIterator<Item = Vec<u8>>>(&mut self, iter: II) {
        for it in iter {
            self.insert(it)
        }
    }
}

impl FromIterator<Vec<u8>> for Hash2Code {
    fn from_iter<II: IntoIterator<Item = Vec<u8>>>(iter: II) -> Self {
        let mut this = Self::new();
        this.extend(iter);
        this
    }
}
