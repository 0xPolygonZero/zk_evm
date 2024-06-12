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

    use mpt_trie_type_1::partial_trie::PartialTrie as _;

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

    #[test]
    fn test() {
        use insta::assert_debug_snapshot;
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
                .skip(1)
        {
            if ix != 1 {
                continue;
            }

            let (their_instructions, their_execution, their_reshaped) =
                crate::compact::compact_prestate_processing::testme(&case.bytes);

            let instructions = wire::parse(&case.bytes).unwrap();

            assert_eq!(
                their_instructions,
                instructions
                    .clone()
                    .into_iter()
                    .map(instruction2instruction)
                    .collect::<Vec<_>>(),
            );

            let executions = execution::execute(instructions).unwrap();
            assert_eq!(executions.len(), 1);
            let execution = executions.first().clone();

            assert_eq!(their_execution, execution2node(execution.clone()));

            let reshaped = reshape::reshape(execution).unwrap();
            dbg!(&reshaped);
            assert_eq!(
                reshaped.state.hash(),
                primitive_types::H256::from_slice(&case.expected_state_root)
            )
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

    #[test]
    fn nibble_test() {
        macro_rules! u4 {
            ($expr:expr) => {{
                use $crate::type1::u4::U4;
                const CONST: U4 = match U4::new($expr) {
                    Some(it) => it,
                    None => panic!(),
                };
                CONST
            }};
        }

        let (a, b, c) = (u4!(1), u4!(2), u4!(3));
        let mut ours = vec![a, b];
        ours.splice(0..0, vec![c]);
        // ours.append(&mut vec![c]);
        let ours = nibbles2nibbles(ours);
        let theirs = nibbles2nibbles(vec![a, b]).merge_nibbles(&nibbles2nibbles(vec![c]));
        assert_eq!(ours, theirs)
    }

    fn nibbles2nibbles(ours: Vec<u4::U4>) -> mpt_trie_type_1::nibbles::Nibbles {
        ours.into_iter().fold(
            mpt_trie_type_1::nibbles::Nibbles::default(),
            |mut acc, el| {
                acc.push_nibble_front(el as u8);
                acc
            },
        )
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
