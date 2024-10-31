//! An implementation of a Type 1 zk-EVM by Polygon Zero.
//!
//! Following the [zk-EVM classification of V. Buterin](https://vitalik.eth.limo/general/2022/08/04/zkevm.html),
//! the evm_arithmetization crate aims at providing an efficient solution for
//! the problem of generating cryptographic proofs of Ethereum-like transactions
//! with *full Ethereum capability*.
//!
//! To this end, the plonky2 zk-EVM is tailored for an AIR-based STARK system
//! satisfying degree 3 constraints, with support for recursive aggregation
//! leveraging plonky2 circuits with FRI-based plonkish arithmetization.
//! These circuits require a one-time, offline preprocessing phase.
//! See the [`fixed_recursive_verifier`] module for more details on how this
//! works. These preprocessed circuits are gathered within the
//! [`AllRecursiveCircuits`] prover state, and can be generated as such:
//!
//! ```ignore
//! // Specify the base field to use.
//! type F = GoldilocksField;
//! // Specify the extension degree to use.
//! const D: usize = 2;
//! // Specify the recursive configuration to use, here leveraging Poseidon hash
//! // over the Goldilocks field both natively and in-circuit.
//! type C = PoseidonGoldilocksConfig;
//!
//! let all_stark = AllStark::<F, D>::default();
//! let config = StarkConfig::standard_fast_config();
//!
//! // Generate all the recursive circuits needed to generate succinct proofs for blocks.
//! // The ranges correspond to the supported table sizes for each individual STARK component.
//! let prover_state = AllRecursiveCircuits::<F, C, D>::new(
//!     &all_stark,
//!     &[16..25, 10..20, 12..25, 14..25, 9..20, 12..20, 17..30],
//!     &config,
//! );
//! ```
//!
//! # Inputs type
//!
//! Transactions need to be processed into an Intermediary Representation (IR)
//! format for the prover to be able to generate proofs of valid state
//! transition. This involves passing the encoded transactions, the header of
//! the block in which they were included, some information on the state prior
//! execution of these transactions, etc.
//! This intermediary representation is called [`GenerationInputs`], although
//! the prover may sometimes rely on a trimmed version,
//! [`TrimmedGenerationInputs`], if some initial data processing already
//! happened.
//!
//!
//! # Generating succinct proofs
//!
//! ## Segment proofs
//!
//! To generate a proof for a batch of transactions,
//! given their [`GenerationInputs`] and an [`AllRecursiveCircuits`] prover
//! state, we first break the execution down into consecutive segments, each
//! representing a partial run of the zkCPU over these inputs. For this step,
//! one must first generate the data needed for each of these segments by
//! initializing a [`SegmentDataIterator`] from the inputs and an optional
//! maximum segment length, and running it until exhaustion. One can then call
//! the [prove_segment](AllRecursiveCircuits::prove_segment) method over each of
//! these obtained segment data independently to generate individual segment
//! proofs:
//!
//! ```ignore
//! type F = GoldilocksField;
//!
//! let mut timing = TimingTree::new("prove", log::Level::Debug);
//! let kill_signal = None; // Useful only with distributed proving to kill hanging jobs.
//!
//! // Collect the segment data needed to prove this batch.
//! let data_iterator =
//!     SegmentDataIterator::<Field>::new(inputs, Some(max_segment_log_length));
//!
//! // Prove all segments associated to this batch
//! let mut segment_proof_data = vec![];
//! for segment_run in data_iterator {
//!     let (_, mut segment_data) = segment_run?;
//!     segment_proof_data.push(
//!         prover_state.prove_segment(
//!             all_stark,
//!             config,
//!             inputs,
//!             segment_data,
//!             &mut timing,
//!             kill_signal
//!         )?
//!     );
//! }
//! ```
//!
//! The [prove_segment](AllRecursiveCircuits::prove_segment) method outputs a
//! segment proof and its associated public values. Public values are also
//! directly retrievable from the proof's encoded public inputs, as such:
//!
//! ```ignore
//! let public_values = PublicValues::from_public_inputs(&proof.public_inputs);
//! ```
//!
//! ## Segment aggregation proofs
//!
//! To improve parallelism and overall proving costs, segments of
//! execution can be proven independently once their associated data have been
//! generated, and are then aggregated together in a binary tree fashion,
//! where each inner node proof verifies two children proofs, through the
//! [prove_segment_aggregation](AllRecursiveCircuits::prove_segment_aggregation)
//! method. Note that the tree does *not* need to be complete, as this
//! aggregation process can take as inputs both simple segment proofs and
//! aggregated segment proofs. We only need to specify for each child which
//! type of proof it corresponds to.
//!
//! ```ignore
//! let (proof_1, pv_1) =
//!     prover_state.prove_segment(all_stark, config, inputs_1, &mut timing, None);
//! let (proof_2, pv_2) =
//!     prover_state.prove_segment(all_stark, config, inputs_2, &mut timing, None);
//! let (proof_3, pv_3) =
//!     prover_state.prove_segment(all_stark, config, inputs_3, &mut timing, None);
//!
//! // Now aggregate proofs for segments 1 and 2.
//! let agg_proof_1_2 =
//!     prover_state.prove_segment_aggregation(proof_1, proof_2);
//!
//! // Now aggregate the newly generated aggregation proof with the last regular segment proof.
//! let agg_proof_1_3 =
//!     prover_state.prove_segment_aggregation(agg_proof_1_2, proof_3);
//! ```
//!
//! **Note**: The proofs provided to the
//! [prove_segment_aggregation](AllRecursiveCircuits::prove_segment_aggregation)
//! method *MUST* have contiguous states. Trying to combine `proof_1` and
//! `proof_3` from the example above, or reverting the order of `agg_proof_1_2`
//! and `proof_3`, would fail.
//!
//! ## Batch aggregation proofs
//!
//! In a similar manner to the previous stage, once an entire batch of
//! transaction has been proven and reduced to a single segment aggregation
//! proof, it can then be combined with other batch proofs or aggregated batch
//! proofs, through the
//! [prove_batch_aggregation](AllRecursiveCircuits::prove_batch_aggregation)
//! method.
//!
//! ```ignore
//! let batch_agg_proof =
//!     prover_state.prove_batch_aggregation(false, batch_proof_1, false, batch_proof_2);
//!
//! // Now aggregate the newly generated batch aggregation proof with the last regular batch proof.
//! let batch_agg_proof =
//!     prover_state.prove_batch_aggregation(batch_agg_proof, batch_proof_3);
//! ```
//!
//! ## Block proofs
//!
//! Once all transactions of a block have been proven and we are left with a
//! single aggregated batch proof and its public values, we can then wrap it
//! into a final block proof, attesting validity of the entire block.
//! This [prove_block](AllRecursiveCircuits::prove_block) method accepts an
//! optional previous block proof as argument, which will then try combining the
//! previously proven block with the current one, generating a validity proof
//! for both. Applying this process from genesis would yield a single proof
//! attesting correctness of the entire chain.
//!
//! ```ignore
//! let previous_block_proof = { ... };
//! let block_proof =
//!     prover_state.prove_block(Some(&previous_block_proof), &agg_proof)?;
//! ```
//!
//! ### Checkpoint heights
//!
//! The process of always providing a previous block proof when generating a
//! proof for the current block may yield some undesirable issues. For this
//! reason, the plonky2 zk-EVM supports checkpoint heights. At given block
//! heights, the prover does not have to pass a previous block proof. This would
//! in practice correspond to block heights at which a proof has been generated
//! and sent to L1 for settlement.
//!
//! The only requirement when generating a block proof without passing a
//! previous one as argument is to have the `checkpoint_state_trie_root`
//! metadata in the `PublicValues` of the final aggregation proof be matching
//! the state trie before applying all the included transactions. If this
//! condition is not met, the prover will fail to generate a valid proof.
//!
//!
//! ```ignore
//! let block_proof =
//!     prover_state.prove_block(None, &agg_proof)?;
//! ```
//!
//! ## Wrapped block proofs
//!
//! Public values expose data useful for aggregating intermediate proofs
//! together, but may not be disclosed to verifiers outside of the chain in
//! their entirety. For this purpose, once a chain has aggregated sufficiently
//! many blocks together and wants to ship the final generated proof, it may
//! call the [prove_block_wrapper](AllRecursiveCircuits::prove_block_wrapper)
//! method to obfuscate any non-required chain data. The remaining
//! [FinalPublicValues](proof::FinalPublicValues) contain all the data
//! needed to identify the chain and its claimed state transition between two
//! checkpoint heights.
//!
//! ```ignore
//! let (wrapped_block_proof, final_public_values) =
//!     prover_state.prove_block_wrapper(&block_proof, public_values)?;
//! ```
//!
//! **Note**: Despite its name, the method produces a [`plonky2`] proof, which
//! may not be suitable for direct on-chain verification in a smart-contract,
//! unlike pairing-based SNARK proofs.
//!
//! # Prover state serialization
//!
//! Because the recursive circuits only need to be generated once, they can be
//! saved to disk once the preprocessing phase completed successfully, and
//! deserialized on-demand. The plonky2 zk-EVM provides serialization methods to
//! convert the entire prover state to a vector of bytes, and vice-versa.
//! This requires the use of custom serializers for gates and generators for
//! proper recursive circuit encoding. This crate provides default serializers
//! supporting all custom gates and associated generators defined within the
//! [`plonky2`] crate.
//!
//! ```ignore
//! let prover_state = AllRecursiveCircuits::<F, C, D>::new(...);
//!
//! // Default serializers
//! let gate_serializer = DefaultGateSerializer;
//! let generator_serializer = DefaultGeneratorSerializer::<C, D> {
//!     _phantom: PhantomData::<C>,
//! };
//!
//! // Serialize the prover state to a sequence of bytes
//! let bytes = prover_state.to_bytes(false, &gate_serializer, &generator_serializer).unwrap();
//!
//! // Deserialize the bytes into a prover state
//! let recovered_prover_state = AllRecursiveCircuits::<F, C, D>::from_bytes(
//!     &all_circuits_bytes,
//!     false,
//!     &gate_serializer,
//!     &generator_serializer,
//! ).unwrap();
//!
//! assert_eq!(prover_state, recovered_prover_state);
//! ```
//!
//! Note that an entire prover state built with wide ranges may be particularly
//! large (up to ~25 GB), hence serialization methods, while faster than doing
//! another preprocessing, may take some non-negligible time.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::field_reassign_with_default)]
#![feature(let_chains)]

zk_evm_common::check_chain_features!();

// Individual STARK processing units
pub mod arithmetic;
pub mod byte_packing;
pub mod cpu;
pub mod keccak;
pub mod keccak_sponge;
pub mod logic;
pub mod memory;
pub mod memory_continuation;
#[cfg(feature = "cdk_erigon")]
pub mod poseidon;

// Proving system components
pub mod all_stark;
pub mod fixed_recursive_verifier;
mod get_challenges;
pub mod proof;
pub mod prover;
pub mod recursive_verifier;
pub mod verifier;

// Witness generation
pub mod generation;
pub mod witness;

// Utility modules
pub mod curve_pairings;
pub mod extension_tower;
pub mod testing_utils;
pub mod util;
pub mod world;

// Public definitions and re-exports
mod public_types;
pub use public_types::*;
pub use starky::config::StarkConfig;

pub use crate::all_stark::{AllStark, NUM_TABLES};
pub use crate::generation::segments::{GenerationSegmentData, SegmentDataIterator};
