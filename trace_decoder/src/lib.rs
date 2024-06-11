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
            let ours = wire::parse(&case.bytes)
                .unwrap()
                .into_iter()
                .map(instruction2instruction)
                .collect::<Vec<_>>();
            let theirs =
                crate::compact::compact_prestate_processing::parse_just_to_instructions(case.bytes)
                    .unwrap();
            pretty_assertions::assert_eq!(theirs, ours);
        }
    }

    use u4::U4;
    use wire::Instruction;

    fn instruction2instruction(
        ours: Instruction,
    ) -> crate::compact::compact_prestate_processing::Instruction {
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

    fn nibbles2nibbles(ours: Vec<U4>) -> mpt_trie_type_1::nibbles::Nibbles {
        ours.into_iter().fold(
            mpt_trie_type_1::nibbles::Nibbles::default(),
            |mut acc, el| {
                acc.push_nibble_front(el as u8);
                acc
            },
        )
    }
}
