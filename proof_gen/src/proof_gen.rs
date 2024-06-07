//! This module defines the proof generation methods corresponding to the three
//! types of proofs the zkEVM internally handles.

use std::sync::{atomic::AtomicBool, Arc};

use evm_arithmetization::{
    fixed_recursive_verifier::ProverOutputData, prover::GenerationSegmentData, AllStark,
    GenerationInputs, StarkConfig,
};
use hashbrown::HashMap;
use plonky2::{
    gates::noop::NoopGate,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
    util::timing::TimingTree,
};

use crate::{
    proof_types::{
        GeneratedBlockProof, GeneratedSegmentAggProof, GeneratedSegmentProof, GeneratedTxnAggProof,
        SegmentAggregatableProof, TxnAggregatableProof,
    },
    prover_state::ProverState,
    types::{Field, PlonkyProofIntern, EXTENSION_DEGREE},
};

/// A type alias for `Result<T, ProofGenError>`.
pub type ProofGenResult<T> = Result<T, ProofGenError>;

/// A custom error type to handle failure cases during proof generation.
// Plonky2 is still using `anyhow` for proof gen, and since this is a library,
// it's probably best if we at least convert it to a `String`.
#[derive(Debug)]
pub struct ProofGenError(pub String);

impl std::fmt::Display for ProofGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl std::error::Error for ProofGenError {}

impl From<String> for ProofGenError {
    fn from(v: String) -> Self {
        Self(v)
    }
}

/// Generates a transaction proof from some IR data.
pub fn generate_segment_proof(
    p_state: &ProverState,
    gen_inputs: GenerationInputs,
    segment_data: &mut GenerationSegmentData,
    abort_signal: Option<Arc<AtomicBool>>,
) -> ProofGenResult<GeneratedSegmentProof> {
    let output_data = p_state
        .state
        .prove_segment(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            gen_inputs,
            segment_data,
            &mut TimingTree::default(),
            abort_signal,
        )
        .map_err(|err| err.to_string())?;

    let p_vals = output_data.public_values;
    let intern = output_data.proof_with_pis;
    Ok(GeneratedSegmentProof { p_vals, intern })
}

/// Generates an aggregation proof from two child proofs.
///
/// Note that the child proofs may be either transaction or aggregation proofs.
///
/// If a transaction only contains a single segment, this function must still be
/// called to generate a `GeneratedSegmentAggProof`. In that case, you can set
/// `has_dummy` to `true`, and provide an arbitrary proof for the right child.
pub fn generate_segment_agg_proof(
    p_state: &ProverState,
    lhs_child: &SegmentAggregatableProof,
    rhs_child: &SegmentAggregatableProof,
    has_dummy: bool,
) -> ProofGenResult<GeneratedSegmentAggProof> {
    if has_dummy {
        assert!(
            !lhs_child.is_agg(),
            "Cannot have a dummy segment with an aggregation."
        );
    }

    let lhs_prover_output_data = ProverOutputData {
        is_dummy: false,
        proof_with_pis: lhs_child.intern().clone(),
        public_values: lhs_child.public_values(),
    };
    let rhs_prover_output_data = ProverOutputData {
        is_dummy: has_dummy,
        proof_with_pis: rhs_child.intern().clone(),
        public_values: rhs_child.public_values(),
    };
    let agg_output_data = p_state
        .state
        .prove_segment_aggregation(
            lhs_child.is_agg(),
            &lhs_prover_output_data,
            rhs_child.is_agg(),
            &rhs_prover_output_data,
        )
        .map_err(|err| err.to_string())?;

    let p_vals = agg_output_data.public_values;
    let intern = agg_output_data.proof_with_pis;

    Ok(GeneratedSegmentAggProof { p_vals, intern })
}

/// Generates a transaction aggregation proof from two child proofs.
///
/// Note that the child proofs may be either transaction or aggregation proofs.
pub fn generate_transaction_agg_proof(
    p_state: &ProverState,
    lhs_child: &TxnAggregatableProof,
    rhs_child: &TxnAggregatableProof,
) -> ProofGenResult<GeneratedTxnAggProof> {
    let (b_proof_intern, p_vals) = p_state
        .state
        .prove_transaction_aggregation(
            lhs_child.is_agg(),
            lhs_child.intern(),
            lhs_child.public_values(),
            rhs_child.is_agg(),
            rhs_child.intern(),
            rhs_child.public_values(),
        )
        .map_err(|err| err.to_string())?;

    Ok(GeneratedTxnAggProof {
        p_vals,
        intern: b_proof_intern,
    })
}

/// Generates a block proof.
///
/// It takes an optional argument, `prev_opt_parent_b_proof`, that can be set to
/// `None` on checkpoint heights.
pub fn generate_block_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedTxnAggProof,
) -> ProofGenResult<GeneratedBlockProof> {
    let b_height = curr_block_agg_proof
        .p_vals
        .block_metadata
        .block_number
        .low_u64();
    let parent_intern = prev_opt_parent_b_proof.map(|p| &p.intern);

    let (b_proof_intern, _) = p_state
        .state
        .prove_block(
            parent_intern,
            &curr_block_agg_proof.intern,
            curr_block_agg_proof.p_vals.clone(),
        )
        .map_err(|err| err.to_string())?;

    Ok(GeneratedBlockProof {
        b_height,
        intern: b_proof_intern,
    })
}

/// Generates a dummy proof for a dummy circuit doing nothing.
/// This is useful for testing purposes only.
pub fn dummy_proof() -> ProofGenResult<PlonkyProofIntern> {
    let mut builder = CircuitBuilder::<Field, EXTENSION_DEGREE>::new(CircuitConfig::default());
    builder.add_gate(NoopGate, vec![]);
    let circuit_data = builder.build::<_>();

    plonky2::recursion::dummy_circuit::dummy_proof(&circuit_data, HashMap::default())
        .map_err(|e| ProofGenError(e.to_string()))
}
