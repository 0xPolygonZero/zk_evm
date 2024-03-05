//! This module defines the proof generation methods corresponding to the three
//! types of proofs the zkEVM internally handles.

use std::sync::{atomic::AtomicBool, Arc};

use evm_arithmetization::{AllStark, StarkConfig};
use plonky2::util::timing::TimingTree;
use trace_decoder::types::TxnProofGenIR;

use crate::{
    proof_types::{AggregatableProof, GeneratedAggProof, GeneratedBlockProof, GeneratedTxnProof},
    prover_state::ProverState,
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
pub fn generate_txn_proof(
    p_state: &ProverState,
    gen_inputs: TxnProofGenIR,
    abort_signal: Option<Arc<AtomicBool>>,
) -> ProofGenResult<GeneratedTxnProof> {
    // TODO: change the `max_cpu_len_log` and `segment_index` arguments once we can
    // automatically determine them.
    let output_data = p_state
        .state
        .prove_segment(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            gen_inputs,
            32,
            0,
            &mut TimingTree::default(),
            abort_signal,
        )
        .map_err(|err| err.to_string())?;

    let p_vals = output_data.public_values;
    let intern = output_data.proof_with_pis;
    Ok(GeneratedTxnProof { p_vals, intern })
}

/// Generates an aggregation proof from two child proofs.
///
/// Note that the child proofs may be either transaction or aggregation proofs.
pub fn generate_agg_proof(
    p_state: &ProverState,
    lhs_child: &AggregatableProof,
    rhs_child: &AggregatableProof,
) -> ProofGenResult<GeneratedAggProof> {
    let (intern, p_vals) = p_state
        .state
        .prove_segment_aggregation(
            lhs_child.is_agg(),
            lhs_child.intern(),
            lhs_child.public_values(),
            rhs_child.is_agg(),
            rhs_child.intern(),
            rhs_child.public_values(),
        )
        .map_err(|err| err.to_string())?;

    Ok(GeneratedAggProof { p_vals, intern })
}

/// Generates a transaction aggregation proof from two child proofs.
///
/// Note that the child proofs may be either transaction or aggregation proofs.
pub fn generate_transaction_agg_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedAggProof,
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

/// Generates a block proof.
///
/// It takes an optional argument, `prev_opt_parent_b_proof`, that can be set to
/// `None` on checkpoint heights.
pub fn generate_block_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedAggProof,
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
