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

zk_evm_common::check_chain_features!();

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

use ethereum_types::{Address, U256};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use evm_arithmetization::GenerationInputs;
use keccak_hash::keccak as hash;
use keccak_hash::H256;
use mpt_trie::partial_trie::{HashedPartialTrie, OnOrphanedHashNode};
use processed_block_trace::ProcessedTxnBatchInfo;
use serde::{Deserialize, Serialize};
use typed_mpt::{StateMpt, StateTrie as _, StorageTrie, TrieKey};

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

    /// A collection of contract code.
    /// This will be accessed by its hash internally.
    #[serde(default)]
    pub code_db: BTreeSet<Vec<u8>>,

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
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
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

    /// True if the account got self-destructed at the end of this txn.
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
    /// Address to store the base fee to be burnt.
    /// Will be `None` when `cdk_erigon` feature flag is off.
    pub burn_addr: Option<Address>,
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
    mut batch_size: usize,
) -> anyhow::Result<Vec<GenerationInputs>> {
    use anyhow::Context as _;
    use mpt_trie::partial_trie::PartialTrie as _;

    use crate::processed_block_trace::{
        Hash2Code, ProcessedBlockTrace, ProcessedBlockTracePreImages,
    };
    use crate::PartialTriePreImages;
    use crate::{
        BlockTraceTriePreImages, CombinedPreImages, SeparateStorageTriesPreImage,
        SeparateTriePreImage, SeparateTriePreImages,
    };

    let BlockTrace {
        trie_pre_images,
        code_db,
        txn_info,
    } = trace;

    let pre_images = match trie_pre_images {
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(storage),
        }) => ProcessedBlockTracePreImages {
            tries: PartialTriePreImages {
                state: state.items().try_fold(
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
                )?,
                storage: storage
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
                    .collect::<Result<_, _>>()?,
            },
            extra_code_hash_mappings: None,
        },
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let instructions =
                wire::parse(&compact).context("couldn't parse instructions from binary format")?;
            let type1::Frontend {
                state,
                code,
                storage,
            } = type1::frontend(instructions)?;
            ProcessedBlockTracePreImages {
                tries: PartialTriePreImages {
                    state,
                    storage: storage.into_iter().collect(),
                },
                extra_code_hash_mappings: match code.is_empty() {
                    true => None,
                    false => Some(
                        code.into_iter()
                            .map(|it| (crate::hash(&it), it.into_vec()))
                            .collect(),
                    ),
                },
            }
        }
    };

    let all_accounts_in_pre_images = pre_images.tries.state.iter().collect::<Vec<_>>();

    // Note we discard any user-provided hashes.
    let mut hash2code = code_db
        .into_iter()
        .chain(
            pre_images
                .extra_code_hash_mappings
                .unwrap_or_default()
                .into_values(),
        )
        .collect::<Hash2Code>();

    // Make sure the batch size is smaller than the total number of transactions,
    // or we would need to generate dummy proofs for the aggregation layers.
    if batch_size > txn_info.len() {
        batch_size = txn_info.len() / 2 + 1;
    }

    let last_tx_idx = txn_info.len().saturating_sub(1) / batch_size;

    let mut txn_info = txn_info
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

            TxnInfo::into_processed_txn_info(
                t,
                &pre_images.tries,
                &all_accounts_in_pre_images,
                &extra_state_accesses,
                &mut hash2code,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    while txn_info.len() < 2 {
        txn_info.push(ProcessedTxnBatchInfo::default());
    }

    decoding::into_txn_proof_gen_ir(
        ProcessedBlockTrace {
            tries: pre_images.tries,
            txn_info,
            withdrawals: other.b_data.withdrawals.clone(),
        },
        other,
        batch_size,
    )
}

#[derive(Debug, Default)]
struct PartialTriePreImages {
    pub state: StateMpt,
    pub storage: HashMap<H256, StorageTrie>,
}

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

trait TryIntoExt<T> {
    type Error: std::error::Error + Send + Sync + 'static;
    fn try_into(self) -> Result<T, Self::Error>;
}

impl<ThisT, T, E> TryIntoExt<T> for ThisT
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
