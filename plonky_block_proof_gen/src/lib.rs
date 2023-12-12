//! This library is intended to generate proofs with the [plonky2 zkEVM](https://github.com/0xPolygonZero/plonky2/evm), given
//! transactions provided in Intermediate Representation (IR) format.
//!
//! The exact format of this IR is defined by the [GenerationInputs](https://github.com/0xPolygonZero/plonky2/evm/src/generation/mod.rs)
//! used by the zkEVM prover, containing an RLP-encoded transaction along with
//! state metadata prior and post execution of this transaction.
//!
//! # Usage
//!
//! First, a prover needs to initialize its `ProverState`. For this, one can
//! use the `ProverStateBuilder`, which contains the ranges to be used by all
//! internal STARK tables of the zkEVM.
//!
//! The default method contains an initial set of ranges for each table, that
//! can be overridden at will by calling
//! `ProverStateBuilder::set_foo_circuit_size` where `foo` is the name of the
//! targeted table. At the moment, plonky2 zkEVM contains seven tables:
//! `arithmetic`, `byte_packing`, `cpu`, `keccak`, `keccak_sponge`, `logic` and
//! `memory`.
//!
//! ```no_run
//!     # use plonky_block_proof_gen::prover_state::ProverStateBuilder;
//!     let mut builder = ProverStateBuilder::default();
//!     
//!     // Change Cpu and Memory tables supported ranges.
//!     let builder = builder
//!         .set_cpu_circuit_size(12..25)
//!         .set_memory_circuit_size(18..28);
//!
//!     // Generate a `ProverState` from the builder.
//!     let prover_state = builder.build();
//! ```
//!
//! ***NOTE***: All the circuits to generate the different kind of proofs, from
//! transaction proofs to block proofs, are specific to the initial set of
//! ranges selected for each table. Changing one of them will require building a
//! new `ProverState`, and will make all previously generated proofs
//! incompatible with the new state. Make sure you select sufficiently large
//! ranges for your application!
//!
//! Once all circuits have been pre-processed, a prover can now generate proofs
//! from inputs passed as Intermediary Representation.
//!
//! This library handles the 3 kinds of proof generations necessary for the
//! zkEVM:
//!
//! ### Transaction proofs
//!
//! From a `ProverState` and a transaction processed with some metadata in
//! Intermediate Representation, one can obtain a transaction proof by calling
//! the method below:
//!
//! ```compile_fail
//!  pub fn generate_txn_proof(
//!     p_state: &ProverState,
//!     start_info: TxnProofGenIR,
//! ) -> ProofGenResult<GeneratedTxnProof> { ... }
//! ```
//!
//! The obtained `GeneratedTxnProof` contains the actual proof and some
//! additional data to be used when aggregating this transaction with others.
//!
//! ### Aggregation proofs
//!
//! Two proofs can be aggregated together with a `ProverState`. These `child`
//! proofs can either be transaction proofs, or aggregated proofs themselves.
//! This library abstracts their type behind an `AggregatableProof` enum.
//!
//! ```compile_fail
//!  pub fn generate_agg_proof(
//!     p_state: &ProverState,
//!     lhs_child: &AggregatableProof,
//!     rhs_child: &AggregatableProof,
//! ) -> ProofGenResult<GeneratedAggProof> { ... }
//! ```
//!
//! ### Block proofs
//!
//! Once the prover has obtained a `GeneratedAggProof` corresponding to the
//! entire set of transactions within a block, they can then wrap it into a
//! final `GeneratedBlockProof`. The prover can pass an optional previous
//! block proof as argument to the `generate_block_proof` method, to combine
//! both statement into one, effectively proving an entire chain from genesis
//! through a single final proof.
//!
//! ```compile_fail
//!  pub fn generate_block_proof(
//!     p_state: &ProverState,
//!     prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
//!     curr_block_agg_proof: &GeneratedAggProof,
//! ) -> ProofGenResult<GeneratedBlockProof> { ... }
//! ```

pub mod proof_gen;
pub mod proof_types;
pub mod prover_state;
pub mod types;
