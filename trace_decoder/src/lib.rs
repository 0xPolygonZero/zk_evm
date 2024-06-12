//! This library generates an Intermediary Representation (IR) of
//! a block's transactions, given a [BlockTrace] and some additional
//! data represented by [OtherBlockData].
//!
//! A [BlockTrace] is defined as follows:
//! ```ignore
//! pub struct BlockTrace {
//!     /// The state and storage trie pre-images (i.e. the tries before
//!     /// the execution of the current block) in multiple possible formats.
//!     pub trie_pre_images: BlockTraceTriePreImages,
//!     /// Traces and other info per transaction. The index of the transaction
//!     /// within the block corresponds to the slot in this vec.
//!     pub txn_info: Vec<TxnInfo>,
//! }
//! ```
//! The trie preimages are the hashed partial tries at the
//! start of the block. A [TxnInfo] contains all the transaction data
//! necessary to generate an IR.
//!
//! # Usage
//!
//! [The zero-bin prover](https://github.com/topos-protocol/zero-bin/blob/main/prover/src/lib.rs)
//! provides a use case for this library:
//! ```ignore
//!  pub async fn prove(
//!      // In this example, [self] is a [ProverInput] storing a [BlockTrace] and
//!      // [OtherBlockData].
//!      self,
//!      runtime: &Runtime,
//!      previous: Option<PlonkyProofIntern>,
//!  ) -> Result<GeneratedBlockProof> {
//!      let block_number = self.get_block_number();
//!      info!("Proving block {block_number}");
//!
//!      let other_data = self.other_data;
//!      // The method calls [into_txn_proof_gen_ir] (see below) to
//!      // generate an IR for each block transaction.
//!      let txs = self.block_trace.into_txn_proof_gen_ir(
//!          &ProcessingMeta::new(resolve_code_hash_fn),
//!          other_data.clone(),
//!      )?;
//!
//!      // The block IRs are provided to the prover to generate an
//!      // aggregation proof.
//!      let agg_proof = IndexedStream::from(txs)
//!          .map(&TxProof)
//!          .fold(&AggProof)
//!          .run(runtime)
//!          .await?;
//!
//!      
//!      if let AggregatableProof::Agg(proof) = agg_proof {
//!          let prev = previous.map(|p| GeneratedBlockProof {
//!              b_height: block_number.as_u64() - 1,
//!              intern: p,
//!          });
//!
//!          // The final aggregation proof is then used to prove the
//!          // current block.
//!          let block_proof = Literal(proof)
//!              .map(&BlockProof { prev })
//!              .run(runtime)
//!              .await?;
//!
//!          info!("Successfully proved block {block_number}");
//!          Ok(block_proof.0)
//!      } else {
//!          bail!("AggProof is is not GeneratedAggProof")
//!      }
//!  }
//! ```
//!
//! As we see in the example, to turn a [BlockTrace] into a
//! vector of IRs, one must call the method
//! [into_txn_proof_gen_ir](BlockTrace::into_txn_proof_gen_ir):
//! ```ignore
//! pub fn into_txn_proof_gen_ir<F>(
//!     self,
//!     // Specifies the way code hashes should be dealt with.
//!     p_meta: &ProcessingMeta<F>,
//!     // Extra data needed for proof generation.
//!     other_data: OtherBlockData,
//! ) -> TraceParsingResult<Vec<GenerationInputs>>
//! ```
//!
//! It first preprocesses the [BlockTrace] to provide transaction,
//! withdrawals and tries data that can be directly used to generate an IR.
//! For each transaction,
//! [into_txn_proof_gen_ir](BlockTrace::into_txn_proof_gen_ir) extracts the
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

#![feature(linked_list_cursors)]
#![feature(trait_alias)]
#![feature(iter_array_chunks)]

pub use decoding::TraceParsingError;
pub use processed_block_trace::ProcessingMeta;

/// Provides debugging tools and a compact representation of state and storage
/// tries, used in tests.
mod compact;
/// Defines the main functions used to generate the IR.
mod decoding;
mod deserializers;
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
mod processed_block_trace;
/// Defines multiple types used in the other modules.
mod types;
/// Defines useful functions necessary to the other modules.
mod utils;

// ! The trace protocol for sending proof information to a prover scheduler.
// !
// ! Because parsing performance has a very negligible impact on overall proof
// ! generation latency & throughput, the overall priority of this protocol is
// ! ease of implementation for clients. The flexibility comes from giving
// ! multiple ways to the client to provide the data for the protocol, where the
// ! implementors can pick whichever way is the most convenient for them.
// !
// ! It might not be obvious why we need traces for each txn in order to
// generate ! proofs. While it's true that we could just run all the txns of a
// block in an ! EVM to generate the traces ourselves, there are a few major
// downsides: ! - The client is likely a full node and already has to run the
// txns in an EVM !   anyways.
// ! - We want this protocol to be as agnostic as possible to the underlying
// !   chain that we're generating proofs for, and running our own EVM would
// !   likely cause us to loose this genericness.
// !
// ! While it's also true that we run our own zk-EVM (plonky2) to generate
// ! proofs, it's critical that we are able to generate txn proofs in parallel.
// ! Since generating proofs with plonky2 is very slow, this would force us to
// ! sequentialize the entire proof generation process. So in the end, it's
// ideal ! if we can get this information sent to us instead.
use std::collections::HashMap;

use ethereum_types::Address;
use ethereum_types::U256;
use mpt_trie_type_1::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, FromInto, TryFromInto};

use crate::{
    deserializers::ByteString,
    types::{CodeHash, HashedAccountAddr, StorageAddr, StorageVal},
    utils::hash,
};

/// Core payload needed to generate a proof for a block. Note that the scheduler
/// may need to request some additional data from the client along with this in
/// order to generate a proof.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The trie pre-images (state & storage) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// Traces and other info per txn. The index of the txn corresponds to the
    /// slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateTriePreImage,
    /// Storage trie.
    pub storage: SeparateStorageTriesPreImage,
}

/// A trie pre-image where state & storage are separate.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateTriePreImage {
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(TrieDirect),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    /// Compact combined state and storage tries.
    pub compact: TrieCompact,
}

// TODO
#[serde_as]
/// Compact representation of a trie (will likely be very close to <https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md>)
#[derive(Debug, Deserialize, Serialize)]
pub struct TrieCompact(#[serde_as(as = "FromInto<ByteString>")] pub Vec<u8>);

// TODO
/// Trie format that is in exactly the same format of our internal trie format.
/// This is the fastest format for us to processes.
#[derive(Debug, Deserialize, Serialize)]
pub struct TrieDirect(pub HashedPartialTrie);

/// A trie pre-image where state and storage are separate.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<HashedAccountAddr, SeparateTriePreImage>),
}

/// Info specific to txns in the block.
#[derive(Debug, Deserialize, Serialize)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: HashMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

/// Structure holding metadata for one transaction.
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct TxnMeta {
    /// Txn byte code.
    #[serde_as(as = "FromInto<ByteString>")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new txn value inserted into the txn trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde_as(as = "FromInto<ByteString>")]
    pub new_txn_trie_node_byte: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde_as(as = "TryFromInto<ByteString>")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Debug, Deserialize, Serialize)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// Account addresses that were only read by the txn.
    ///
    /// Note that if storage is written to, then it does not need to appear in
    /// this list (but is also fine if it does).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_read: Option<Vec<StorageAddr>>,

    /// Account storage addresses that were mutated by the txn along with their
    /// new value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_written: Option<HashMap<StorageAddr, StorageVal>>,

    /// Contract code that this address accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// True if the account existed before this txn but self-destructed at the
    /// end of this txn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destructed: Option<bool>,
}

/// Contract code access type. Used by txn traces.
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(CodeHash),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde_as(as = "FromInto<ByteString>")] Vec<u8>),
}

impl ContractCodeUsage {
    pub(crate) fn get_code_hash(&self) -> CodeHash {
        match self {
            ContractCodeUsage::Read(hash) => *hash,
            ContractCodeUsage::Write(bytes) => hash(bytes),
        }
    }
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: ethereum_types::H256,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: evm_arithmetization_type_1::proof::BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: evm_arithmetization_type_1::proof::BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(ethereum_types::Address, ethereum_types::U256)>,
}

pub fn legacy(
    block_trace: BlockTrace,
    other_block_data: OtherBlockData,
    resolver: impl Fn(&ethereum_types::H256) -> Vec<u8>,
) -> Result<Vec<evm_arithmetization_type_1::GenerationInputs>, Box<TraceParsingError>> {
    block_trace.into_txn_proof_gen_ir(&ProcessingMeta::new(resolver), other_block_data)
}

pub use type1::type1 as new;

mod type1 {
    //! Based on [this specification](https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout).
    //! Deviations are commented with `BUG`.

    use anyhow::{bail, Context as _};
    use evm_arithmetization_type_1::generation::mpt::AccountRlp;
    use itertools::{Itertools as _, Position};
    use mpt_trie_type_1::{partial_trie::PartialTrie, trie_ops::ValOrHash};

    use crate::{
        compact::compact_prestate_processing::PartialTriePreImages,
        processed_block_trace::{CodeHashResolving, ProcessedBlockTrace},
        *,
    };

    /// Execution of [`Instruction`]s from the wire into a trie.
    ///
    /// Use of a stack machine is amenable to streaming off the wire.
    mod execution;
    mod reshape;
    /// Simple nibble representation.
    mod u4;
    /// Parser combinators for the binary "wire" format.
    ///
    /// Use of [`winnow`] is amenable to streaming off the wire.
    mod wire;

    pub fn type1(
        block_trace: BlockTrace,
        other_block_data: OtherBlockData,
        resolver: impl Fn(&primitive_types::H256) -> Vec<u8>,
    ) -> anyhow::Result<Vec<evm_arithmetization_type_1::GenerationInputs>> {
        // TODO(0xaatif): why is this like this?
        let BlockTrace {
            trie_pre_images:
                BlockTraceTriePreImages::Combined(CombinedPreImages {
                    compact: TrieCompact(bytes),
                }),
            txn_info,
        } = block_trace;

        let instructions =
            wire::parse(&bytes).context("couldn't parse instructions from binary format")?;
        let executions =
            execution::execute(instructions).context("couldn't execute instructions")?;
        if !executions.len() == 1 {
            bail!(
                "only a single execution is supported, not {}",
                executions.len()
            )
        }
        let execution = executions.into_vec().remove(0);
        let reshape::Reshape {
            state,
            code,
            storage,
        } = reshape::reshape(execution).context("couldn't reshape execution")?;

        let all_accounts = state
            .items()
            .filter_map(|(nibs, vh)| match vh {
                ValOrHash::Val(v) => Some((
                    primitive_types::H256::from(nibs),
                    rlp::decode::<AccountRlp>(&v).ok()?,
                )),
                ValOrHash::Hash(_) => None,
            })
            .collect::<Vec<_>>();

        let mut resolver = CodeHashResolving {
            client_code_hash_resolve_f: resolver,
            extra_code_hash_mappings: code
                .into_iter()
                .map(|it| (crate::utils::hash(&it), it.into()))
                .collect(),
        };

        let gis = ProcessedBlockTrace {
            tries: PartialTriePreImages {
                state,
                storage: storage.into_iter().collect(),
            },
            txn_info: txn_info
                .into_iter()
                .with_position()
                .map(|(pos, txn_info)| {
                    let extra_state_accesses = match pos {
                        Position::First | Position::Middle => Vec::new(),
                        Position::Last | Position::Only => other_block_data
                            .b_data
                            .withdrawals
                            .iter()
                            .map(|(addr, _)| crate::utils::hash(addr.as_bytes()))
                            .collect(),
                    };
                    txn_info.into_processed_txn_info(
                        &all_accounts,
                        &extra_state_accesses,
                        &mut resolver,
                    )
                })
                .collect(),
            // TODO(0xaatif): why is this duplicated?
            withdrawals: other_block_data.b_data.withdrawals.clone(),
        }
        .into_txn_proof_gen_ir(other_block_data)
        .context("couldn't process proof gen IR")?;

        Ok(gis)
    }

    #[test]
    fn test() {
        use insta::assert_debug_snapshot;
        use mpt_trie_type_1::partial_trie::PartialTrie as _;
        use pretty_assertions::assert_eq;

        #[derive(serde::Deserialize)]
        struct Case {
            #[serde(with = "hex")]
            pub bytes: Vec<u8>,
            #[serde(with = "hex", default)]
            pub expected_state_root: Vec<u8>,
        }

        for (ix, case) in
            serde_json::from_str::<Vec<Case>>(include_str!("type1/witness_vectors.json"))
                .unwrap()
                .into_iter()
                .enumerate()
        {
            println!("case {}", ix);
            let (their_instructions, their_execution, their_reshaped) =
                crate::compact::compact_prestate_processing::testme(&case.bytes);

            let instructions = wire::parse(&case.bytes).unwrap();
            assert_debug_snapshot!(instructions);

            assert_eq!(
                their_instructions,
                instructions
                    .clone()
                    .into_iter()
                    .map(instruction2instruction)
                    .collect::<Vec<_>>(),
            );

            let executions = execution::execute(instructions).unwrap();
            assert_debug_snapshot!(executions);
            assert_eq!(executions.len(), 1);
            let execution = executions.first().clone();

            assert_eq!(their_execution, execution2node(execution.clone()));

            let reshaped = reshape::reshape(execution).unwrap();
            assert_debug_snapshot!(reshaped);
            assert_eq!(
                reshaped.state.hash(),
                primitive_types::H256::from_slice(&case.expected_state_root)
            );

            for (k, v) in reshaped.state.items() {
                if let ValOrHash::Val(bytes) = v {
                    let storage_root = rlp::decode::<
                        evm_arithmetization_type_1::generation::mpt::AccountRlp,
                    >(&bytes)
                    .unwrap()
                    .storage_root;
                    if storage_root != crate::utils::hash(&[]) {
                        assert!(reshaped
                            .storage
                            .contains_key(&primitive_types::H256::from_slice(&k.bytes_be())))
                    }
                }
            }
        }
    }

    fn instruction2instruction(
        ours: wire::Instruction,
    ) -> crate::compact::compact_prestate_processing::Instruction {
        use wire::Instruction;

        use crate::compact::compact_prestate_processing::Instruction as Theirs;
        match ours {
            Instruction::Leaf { key, value } => {
                Theirs::Leaf(nibbles2nibbles(key.into()), value.into())
            }
            Instruction::Extension { key } => Theirs::Extension(nibbles2nibbles(key.into())),
            Instruction::Branch { mask } => Theirs::Branch(mask.try_into().unwrap()),
            Instruction::Hash { raw_hash } => Theirs::Hash(raw_hash.into()),
            Instruction::Code { raw_code } => Theirs::Code(raw_code.into()),
            Instruction::AccountLeaf {
                key,
                nonce,
                balance,
                has_code,
                has_storage,
            } => Theirs::AccountLeaf(
                nibbles2nibbles(key.into()),
                nonce.unwrap_or_default().into(),
                balance.unwrap_or_default(),
                has_code,
                has_storage,
            ),
            Instruction::EmptyRoot => Theirs::EmptyRoot,
            Instruction::NewTrie => todo!(),
        }
    }

    fn nibbles2nibbles(ours: Vec<u4::U4>) -> mpt_trie_type_1::nibbles::Nibbles {
        let mut theirs = mpt_trie_type_1::nibbles::Nibbles::default();
        for it in ours {
            theirs.push_nibble_back(it as u8)
        }
        theirs
    }

    fn execution2node(
        ours: execution::Execution,
    ) -> crate::compact::compact_prestate_processing::NodeEntry {
        use execution::*;
        node2node(match ours {
            Execution::Leaf(it) => Node::Leaf(it),
            Execution::Extension(it) => Node::Extension(it),
            Execution::Branch(it) => Node::Branch(it),
            Execution::Empty => Node::Empty,
        })
    }

    fn node2node(ours: execution::Node) -> crate::compact::compact_prestate_processing::NodeEntry {
        use either::Either;
        use execution::*;

        use crate::compact::compact_prestate_processing::{
            AccountNodeCode, AccountNodeData, LeafNodeData, NodeEntry as Theirs, ValueNodeData,
        };
        match ours {
            Node::Hash(Hash { raw_hash }) => Theirs::Hash(raw_hash.into()),
            Node::Leaf(Leaf { key, value }) => Theirs::Leaf(
                nibbles2nibbles(key.into()),
                match value {
                    Either::Left(Value { raw_value }) => {
                        LeafNodeData::Value(ValueNodeData(raw_value.into()))
                    }
                    Either::Right(Account {
                        nonce,
                        balance,
                        storage,
                        code,
                    }) => LeafNodeData::Account(AccountNodeData {
                        nonce: nonce.into(),
                        balance,
                        storage_trie: storage.map(|it| reshape::node2trie(*it).unwrap()),
                        account_node_code: code.map(|it| match it {
                            Either::Left(Hash { raw_hash }) => {
                                AccountNodeCode::HashNode(raw_hash.into())
                            }
                            Either::Right(Code { code }) => AccountNodeCode::CodeNode(code.into()),
                        }),
                    }),
                },
            ),
            Node::Extension(Extension { key, child }) => {
                Theirs::Extension(nibbles2nibbles(key.into()), Box::new(node2node(*child)))
            }
            Node::Branch(Branch { children }) => {
                Theirs::Branch(children.map(|it| it.map(|it| Box::new(node2node(*it)))))
            }
            Node::Code(Code { code }) => Theirs::Code(code.into()),
            Node::Empty => Theirs::Empty,
        }
    }
}
