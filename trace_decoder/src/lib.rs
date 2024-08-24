//! <div class="warning">
//! This library is undergoing major refactoring as part of (#275)(https://github.com/0xPolygonZero/zk_evm/issues/275).
//! Consider all TODOs to be tracked under that issue.
//! </div>
//!
//! Your neighborhood zk-ready [ethereum](https://github.com/0xPolygonZero/erigon)
//! [node](https://github.com/0xPolygonHermez/cdk-erigon/) emits binary "witnesses"[^1].
//!
//! But [`plonky2`], your prover, wants [`GenerationInputs`].
//!
//! This library helps you get there.
//!
//! [^1]: A witness is an attestation of the state of the world, which can be
//!       proven by a prover.
//!
//! # Non-Goals
//! - Performance - this won't be the bottleneck in any proving system.
//! - Robustness - malicious or malformed input may crash this library.
//!
//! TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
//!                refactor all the docs below
//!
//! It might not be obvious why we need traces for each txn in order to generate
//! proofs. While it's true that we could just run all the txns of a block in an
//! EVM to generate the traces ourselves, there are a few major downsides:
//! - The client is likely a full node and already has to run the txns in an EVM
//!   anyways.
//! - We want this protocol to be as agnostic as possible to the underlying
//!   chain that we're generating proofs for, and running our own EVM would
//!   likely cause us to loose this genericness.
//!
//! While it's also true that we run our own zk-EVM (plonky2) to generate
//! proofs, it's critical that we are able to generate txn proofs in parallel.
//! Since generating proofs with plonky2 is very slow, this would force us to
//! sequentialize the entire proof generation process. So in the end, it's ideal
//! if we can get this information sent to us instead.
//!
//! This library generates an Intermediary Representation (IR) of
//! a block's transactions, given a [BlockTrace] and some additional
//! data represented by [OtherBlockData].
//!
//! It first preprocesses the [BlockTrace] to provide transaction,
//! withdrawals and tries data that can be directly used to generate an IR.
//! For each transaction, this library extracts the
//! necessary data from the processed transaction information to
//! return the IR.
//!
//! The IR is used to generate root proofs, then aggregation proofs and finally
//! block proofs. Because aggregation proofs require at least two entries, we
//! pad the vector of IRs thanks to additional dummy payload intermediary
//! representations whenever necessary.
//!
//! ### [Withdrawals](https://ethereum.org/staking/withdrawals) and Padding
//!
//! Withdrawals are all proven together in a dummy payload. A dummy payload
//! corresponds to the IR of a proof with no transaction. They must, however, be
//! proven last. The padding is therefore carried out as follows: If there are
//! no transactions in the block, we add two dummy transactions. The withdrawals
//! -- if any -- are added to the second dummy transaction. If there is only one
//! transaction in the block, we add one dummy transaction. If
//! there are withdrawals, the dummy transaction is at the end. Otherwise, it is
//! added at the start. If there are two or more transactions:
//! - if there are no withdrawals, no dummy transactions are added
//! - if there are withdrawals, one dummy transaction is added at the end, with
//!   all the withdrawals in it.

#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

/// The broad overview is as follows:
///
/// 1. Ethereum nodes emit a bunch of binary [`wire::Instruction`]s, which are
///    parsed in [`wire`].
/// 2. They are passed to one of two "frontends", depending on the node
///    - [`type2`], which contains an [`smt_trie`].
///    - [`type1`], which contains an [`mpt_trie`].
/// 3. The frontend ([`type1::Frontend`] or [`type2::Frontend`]) is passed to
///    the "backend", which lowers to [`evm_arithmetization::GenerationInputs`].
///
/// Deviations from the specification are signalled with `BUG(spec)` in the
/// code.
const _DEVELOPER_DOCS: () = ();

/// Defines the main functions used to generate the IR.
mod decoding;
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
mod processed_block_trace;
mod type1;
// TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/275
//                add backend/prod support for type 2
#[cfg(test)]
#[allow(dead_code)]
mod type2;
mod typed_mpt;
mod wire;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;

use anyhow::ensure;
use ethereum_types::{Address, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use evm_arithmetization::GenerationInputs;
use keccak_hash::keccak as hash;
use keccak_hash::H256;
use mpt_trie::partial_trie::{HashedPartialTrie, OnOrphanedHashNode};
use processed_block_trace::{BatchInfo, BatchTouch, Hash2Code, StateWrite};
use serde::{Deserialize, Serialize};
use typed_mpt::{ReceiptTrie, StateMpt, StateTrie as _, StorageTrie, TransactionTrie, TrieKey};

/// Core payload needed to generate proof for a block.
/// Additional data retrievable from the blockchain node (using standard ETH RPC
/// API) may be needed for proof generation.
///
/// The trie preimages are the hashed partial tries at the
/// start of the block. A [TxnInfo] contains all the transaction data
/// necessary to generate an IR.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The state and storage trie pre-images (i.e. the tries before
    /// the execution of the current block) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// The code_db is a map of code hashes to the actual code. This is needed
    /// to execute transactions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub code_db: BTreeMap<H256, Vec<u8>>,

    /// Traces and other info per transaction. The index of the transaction
    /// within the block corresponds to the slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with separate state/storage tries.
    Separate(SeparateTriePreImages),
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateTriePreImage,
    /// Storage trie.
    pub storage: SeparateStorageTriesPreImage,
}

/// A trie pre-image where state & storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateTriePreImage {
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(HashedPartialTrie),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    /// Compact combined state and storage tries.
    #[serde(with = "crate::hex")]
    pub compact: Vec<u8>,
}

/// A trie pre-image where state and storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<H256, SeparateTriePreImage>),
}

/// Info specific to txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: BTreeMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

/// Structure holding metadata for one transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnMeta {
    /// Txn byte code. This is also the raw RLP bytestring inserted into the txn
    /// trie by this txn. Note that the key is not included and this is only
    /// the rlped value of the node!
    #[serde(with = "crate::hex")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde(with = "crate::hex")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TxnTrace {
    /// [`Some`] if the [Account::balance] changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// [`Some`] if the [Account::nonce] changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// <code>[hash](hash)([Address])</code> of storages read by the
    /// transaction.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub storage_read: BTreeSet<H256>,

    /// <code>[hash](hash)([Address])</code> of storages written by the
    /// transaction, with their new value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage_written: BTreeMap<H256, U256>,

    /// Contract code that this account has accessed or created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// `true` if this account got self-destructed at the end of this txn.
    #[serde(default, skip_serializing_if = "is_false")]
    pub self_destructed: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Contract code access type. Used by txn traces.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(H256),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde(with = "crate::hex")] Vec<u8>),
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: H256,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(Address, U256)>,
}

/// TODO(0xaatif): <https://github.com/0xPolygonZero/zk_evm/issues/275>
///                document this once we have the API finalized
pub fn entrypoint(
    trace: BlockTrace,
    other: OtherBlockData,
    batch_size: usize,
) -> anyhow::Result<Vec<GenerationInputs>> {
    use anyhow::Context as _;
    use mpt_trie::partial_trie::PartialTrie as _;

    use crate::processed_block_trace::Hash2Code;
    use crate::{
        BlockTraceTriePreImages, CombinedPreImages, SeparateStorageTriesPreImage,
        SeparateTriePreImage, SeparateTriePreImages,
    };

    let BlockTrace {
        trie_pre_images,
        code_db,
        txn_info: txn_infos,
    } = trace;

    let (state, storage, mut code) = match trie_pre_images {
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => {
            let state = state.items().try_fold(
                StateMpt::new(OnOrphanedHashNode::Reject),
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
                        .try_fold(
                            StorageTrie::new(OnOrphanedHashNode::Reject),
                            |mut acc, (nibbles, hash_or_val)| {
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
                            },
                        )
                        .map(|v| (k, v))
                })
                .collect::<Result<_, _>>()?;
            (state, storage, Hash2Code::new())
        }
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions =
                wire::parse(&compact).context("couldn't parse instructions from binary format")?;
            let type1::Frontend {
                state,
                code,
                storage,
            } = type1::frontend(instructions)?;
            (
                state,
                storage,
                Hash2Code::from_iter(code.into_iter().map(Into::into)),
            )
        }
    };

    // Note we discard any user-provided hashes.
    code.extend(code_db.into_values());

    let last_tx_idx = txn_infos.len().saturating_sub(1) / batch_size;

    let mut batchinfos = txn_infos
        .chunks(batch_size)
        .enumerate()
        .map(|(i, t)| {
            let extra_state_accesses = if last_tx_idx == i {
                // If this is the last transaction, we mark the withdrawal addresses
                // as accessed in the state trie.
                other
                    .b_data
                    .withdrawals
                    .iter()
                    .map(|(addr, _)| *addr)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            TxnInfo::batch(t, &state, &extra_state_accesses, &mut code)
        })
        .collect::<Result<Vec<_>, _>>()?;

    while batchinfos.len() < 2 {
        batchinfos.push(BatchInfo::default());
    }

    decoding::batches2gis(
        state,
        storage,
        batchinfos,
        other.b_data.withdrawals.clone(),
        other,
        batch_size,
    )
}

#[allow(unused, private_interfaces, missing_docs)]
pub fn start(
    // state at the beginning of the block
    state0: StateMpt,
    // storage at the beginning of the block
    mut storage: BTreeMap<H256, StorageTrie>,
    code: &mut Hash2Code,
    batches: Vec<Vec<TxnInfo>>,
    withdrawals: Vec<(Address, U256)>,
) -> anyhow::Result<()> {
    // These are the per-block tries.
    let mut transaction_trie = TransactionTrie::new();
    let mut receipt_trie = ReceiptTrie::new();

    for (haddr, acct) in state0.iter() {
        let storage = storage.entry(haddr).or_insert({
            let mut it = StorageTrie::default();
            it.insert_hash(TrieKey::default(), acct.storage_root)
                .expect("empty trie insert cannot fail");
            it
        });
        ensure!(
            storage.root() == acct.storage_root,
            "bad initial storage for {haddr}"
        )
    }

    let mut txn_ix = 0;
    let final_txn_ix = batches
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        .saturating_sub(1);
    for (batch) in batches {
        let mut per_batch = PerBatch::default();

        for TxnInfo {
            traces,
            meta:
                TxnMeta {
                    byte_code,
                    new_receipt_trie_node_byte,
                    gas_used,
                },
        } in batch
        {
            let mut created_in_txn = BTreeSet::new();
            for (
                addr,
                TxnTrace {
                    balance,
                    nonce,
                    storage_read,
                    storage_written,
                    code_usage,
                    self_destructed,
                },
            ) in traces
            {
                per_batch
                    .storage_accesses
                    .entry(hash(addr))
                    .or_default()
                    .extend(
                        storage_written
                            .keys()
                            .chain(&storage_read)
                            .map(|hash| TrieKey::from_hash(crate::hash(hash))),
                    );

                let storage_trie_change = !storage_written.is_empty();

                for (k, v) in storage_written {
                    per_batch
                        .storage_writes
                        .entry(hash(addr))
                        .or_default()
                        .insert(TrieKey::from_hash(k), rlp::encode(&v).to_vec());
                }

                let state_write = StateWrite {
                    balance,
                    nonce,
                    storage_trie_change,
                    code_hash: code_usage
                        .map(|it| match it {
                            ContractCodeUsage::Read(hash) => {
                                per_batch.accessed_code.insert(code.get(hash)?);
                                anyhow::Ok(hash)
                            }
                            ContractCodeUsage::Write(bytes) => {
                                code.insert(bytes.clone());
                                let hash = hash(&bytes);
                                per_batch.accessed_code.insert(bytes);
                                anyhow::Ok(hash)
                            }
                        })
                        .transpose()?,
                };
                if state_write != StateWrite::default() {
                    // a write occurred

                    // Account creations are flagged to handle reverts.
                    if !state0.contains_address(addr) {
                        created_in_txn.insert(addr);
                    }

                    // Some edge case may see a contract creation followed by a `SELFDESTRUCT`, with
                    // then a follow-up transaction within the same batch updating the state of the
                    // account. If that happens, we should not delete the account after processing
                    // this batch.
                    per_batch.self_destructed.remove(&addr);

                    per_batch
                        .state_writes
                        .entry(addr)
                        .and_modify(
                            |StateWrite {
                                 balance,
                                 nonce,
                                 storage_trie_change,
                                 code_hash,
                             }| {
                                *balance = state_write.balance.or(*balance);
                                *nonce = state_write.nonce.or(*nonce);
                                *code_hash = state_write.code_hash.or(*code_hash);
                                *storage_trie_change =
                                    state_write.storage_trie_change || *storage_trie_change;
                            },
                        )
                        .or_insert(state_write);
                }

                let is_precompile =
                    PRECOMPILE_ADDRESS_RANGE.contains(&U256::from_big_endian(addr.as_bytes()));

                // Trie witnesses will only include accessed precompile accounts as hash
                // nodes if the transaction calling them reverted. If this is the case, we
                // shouldn't include them in this transaction's `state_accesses` to allow the
                // decoder to build a minimal state trie without hitting any hash node.

                if !is_precompile || state0.get_by_address(addr).is_some() {
                    per_batch.state_accesses.insert(addr);
                }

                if self_destructed {
                    per_batch.self_destructed.insert(addr);
                }
            }

            // TODO(0xaatif): in the reference, this is not done
            //                - for dummy transactions
            //                - if `byte_code` is empty
            transaction_trie.insert(txn_ix, byte_code)?;
            receipt_trie.insert(txn_ix, new_receipt_trie_node_byte)?;

            txn_ix += 1;
        }
        //
    }
    Ok(())
}

/// Note that "*_accesses" includes writes.
#[derive(Default)]
struct PerBatch {
    state_writes: BTreeMap<Address, StateWrite>,
    state_accesses: BTreeSet<Address>,

    storage_writes: BTreeMap<H256, BTreeMap<TrieKey, Vec<u8>>>,
    storage_accesses: BTreeMap<H256, Vec<TrieKey>>,

    /// <code>[hash](hash)([Address]) -> [AccountRlp::storage_root]</code>
    accts_with_ignored_storage: BTreeMap<H256, H256>,

    self_destructed: BTreeSet<Address>,
    accessed_code: BTreeSet<Vec<u8>>,
}

// TODO(0xaatif): is this _meant_ to exclude the final member?
const PRECOMPILE_ADDRESS_RANGE: Range<U256> = U256([1, 0, 0, 0])..U256([10, 0, 0, 0]);

/// Like `#[serde(with = "hex")`, but tolerates and emits leading `0x` prefixes
mod hex {
    use serde::{de::Error as _, Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: hex::ToHex,
    {
        let s = data.encode_hex::<String>();
        serializer.serialize_str(&format!("0x{}", s))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(deserializer: D) -> Result<T, D::Error>
    where
        T: hex::FromHex,
        T::Error: std::fmt::Display,
    {
        let s = String::deserialize(deserializer)?;
        match s.strip_prefix("0x") {
            Some(rest) => T::from_hex(rest),
            None => T::from_hex(&*s),
        }
        .map_err(D::Error::custom)
    }
}

trait TryIntoBounds<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    fn try_into(self) -> Result<T, Self::Error>;
}

impl<ThisT, T, E> TryIntoBounds<T> for ThisT
where
    ThisT: TryInto<T, Error = E>,
    E: std::error::Error + Send + Sync + 'static,
{
    type Error = ThisT::Error;

    fn try_into(self) -> Result<T, Self::Error> {
        TryInto::try_into(self)
    }
}

#[cfg(test)]
#[derive(serde::Deserialize)]
struct Case {
    #[serde(with = "hex")]
    pub bytes: Vec<u8>,
    #[serde(deserialize_with = "h256")]
    pub expected_state_root: ethereum_types::H256,
}

#[cfg(test)]
fn h256<'de, D: serde::Deserializer<'de>>(it: D) -> Result<ethereum_types::H256, D::Error> {
    Ok(ethereum_types::H256(hex::deserialize(it)?))
}
