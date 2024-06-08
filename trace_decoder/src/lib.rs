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
pub use trace_protocol::BlockTrace;
pub use types::{CodeHash, OtherBlockData};

/// Provides debugging tools and a compact representation of state and storage
/// tries, used in tests.
mod compact;
/// Defines the main functions used to generate the IR.
mod decoding;
mod deserializers;
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
mod processed_block_trace;
mod trace_protocol;
/// Defines multiple types used in the other modules.
mod types;
/// Defines useful functions necessary to the other modules.
mod utils;

pub fn type_1(
    block_trace: BlockTrace,
    other_block_data: OtherBlockData,
    resolver: impl Fn(&CodeHash) -> Vec<u8>,
) -> Result<Vec<evm_arithmetization_type_1::GenerationInputs>, Box<TraceParsingError>> {
    block_trace.into_txn_proof_gen_ir(&ProcessingMeta::new(resolver), other_block_data)
}

mod type1 {
    //! Based on [this specification](https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout).
    //! Deviations are commented with `BUG`.

    /// Execution of [`Instruction`]s from the wire into a trie.
    ///
    /// Use of a stack machine is amenable to streaming off the wire.
    mod execution;
    /// Parser combinators for the binary "wire" format.
    ///
    /// Use of [`winnow`] is amenable to streaming off the wire.
    mod wire;

    use std::sync::Arc;

    use either::Either;
    use evm_arithmetization_type_1::generation::mpt::AccountRlp;
    use execution::{Account, Branch, Code, Extension, FinalNode, Hash, Leaf, Node, Value};
    use nunny::NonEmpty;

    /// Keep the spec trie separate from our runtime trie.
    fn final_node2node(
        it: execution::FinalNode,
    ) -> mpt_trie_type_1::partial_trie::Node<mpt_trie_type_1::partial_trie::HashedPartialTrie> {
        match it {
            FinalNode::Leaf(it) => leaf2leaf(it),
            FinalNode::Extension(it) => extension2extension(it),
            FinalNode::Branch(it) => branch2branch(it),
            FinalNode::Empty => mpt_trie_type_1::partial_trie::Node::Empty,
        }
    }

    fn branch2branch(
        Branch { children }: Branch,
    ) -> mpt_trie_type_1::partial_trie::Node<mpt_trie_type_1::partial_trie::HashedPartialTrie> {
        mpt_trie_type_1::partial_trie::Node::Branch {
            children: children.map(|it| match it {
                Some(it) => Arc::new(Box::new(node2trie(*it))),
                None => Arc::new(Box::new(node2trie(execution::Node::Empty))),
            }),
            value: todo!(),
        }
    }

    fn extension2extension(
        Extension { key, child }: Extension,
    ) -> mpt_trie_type_1::partial_trie::Node<mpt_trie_type_1::partial_trie::HashedPartialTrie> {
        mpt_trie_type_1::partial_trie::Node::Extension {
            nibbles: key2nibbles(key),
            child: Arc::new(Box::new(node2trie(*child))),
        }
    }

    fn leaf2leaf(
        Leaf { key, value }: Leaf,
    ) -> mpt_trie_type_1::partial_trie::Node<mpt_trie_type_1::partial_trie::HashedPartialTrie> {
        mpt_trie_type_1::partial_trie::Node::Leaf {
            nibbles: key2nibbles(key),
            value: match value {
                Either::Left(Value { raw_value }) => rlp::encode(raw_value.as_vec()).to_vec(),
                Either::Right(Account {
                    nonce,
                    balance,
                    storage,
                    code,
                }) => todo!(),
            },
        }
    }

    fn account2account(
        Account {
            nonce,
            balance,
            storage,
            code,
        }: Account,
    ) -> AccountRlp {
        AccountRlp {
            nonce: nonce.into(),
            balance,
            storage_root: match storage {
                Some(_) => todo!(),
                None => todo!(),
            },
            code_hash: match code {
                Some(Either::Left(Hash { raw_hash })) => todo!(),
                Some(Either::Right(Code { code })) => todo!(),
                None => todo!(),
            },
        }
    }

    fn node2trie(it: execution::Node) -> mpt_trie_type_1::partial_trie::HashedPartialTrie {
        match it {
            Node::Hash(Hash { raw_hash }) => {
                mpt_trie_type_1::partial_trie::Node::Hash(ethereum_types::H256::from(raw_hash))
            }
            Node::Value(Value { raw_value }) => todo!(),
            Node::Account(Account {
                nonce,
                balance,
                storage,
                code,
            }) => todo!(),
            Node::Leaf(it) => leaf2leaf(it),
            Node::Extension(it) => extension2extension(it),
            Node::Branch(it) => branch2branch(it),
            Node::Code(Code { code }) => todo!(),
            Node::Empty => mpt_trie_type_1::partial_trie::Node::Empty,
        }
        .into()
    }

    fn key2nibbles(it: NonEmpty<Vec<u8>>) -> mpt_trie_type_1::nibbles::Nibbles {
        todo!()
    }

    #[test]
    fn test() {
        use insta::assert_debug_snapshot;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Case {
            #[serde(with = "hex", rename = "hex")]
            pub bytes: Vec<u8>,
        }

        for vector in
            serde_json::from_str::<Vec<Case>>(include_str!("type1/witness_vectors.json")).unwrap()
        {
            let instructions = wire::parse(&vector.bytes).unwrap();
            assert_debug_snapshot!(instructions);
            let executed = execution::execute(instructions).unwrap();
            assert_debug_snapshot!(executed);
        }
    }
}
