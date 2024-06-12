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
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

#[cfg(doc)]
use {
    trace_protocol::{BlockTrace, TxnInfo},
    types::OtherBlockData,
};

/// Provides debugging tools and a compact representation of state and storage
/// tries, used in tests.
pub mod compact;
/// Defines the main functions used to generate the IR.
pub mod decoding;
mod deserializers;
/// Defines functions that processes a [BlockTrace] so that it is easier to turn
/// the block transactions into IRs.
pub mod processed_block_trace;
pub mod trace_protocol;
/// Defines multiple types used in the other modules.
pub mod types;
/// Defines useful functions necessary to the other modules.
pub mod utils;
