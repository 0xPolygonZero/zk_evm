use std::time::Instant;

use common::{debug_utils::save_inputs_to_disk, prover_state::p_state};
use evm_arithmetization::{proof::PublicValues, GenerationInputs};
use keccak_hash::keccak;
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof},
    proof_types::{AggregatableProof, GeneratedAggProof, GeneratedBlockProof},
};
use serde::{Deserialize, Serialize};
use tracing::{error, event, info_span, Level};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct TxProof {
    pub save_inputs_on_error: bool,
}

#[cfg(not(feature = "test_only"))]
impl Operation for TxProof {
    type Input = GenerationInputs;
    type Output = proof_gen::proof_types::AggregatableProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let _span = TxProofSpan::new(&input);
        let proof = if self.save_inputs_on_error {
            common::prover_state::p_manager()
                .generate_txn_proof(input.clone())
                .map_err(|err| {
                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "b{}_txn_{}_input.log",
                            input.block_metadata.block_number, input.txn_number_before
                        ),
                        input,
                    ) {
                        error!("Failed to save txn proof input to disk: {:?}", write_err);
                    }

                    FatalError::from_anyhow(err, FatalStrategy::Terminate)
                })?
        } else {
            common::prover_state::p_manager()
                .generate_txn_proof(input)
                .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate))?
        };

        Ok(proof.into())
    }
}

#[cfg(feature = "test_only")]
impl Operation for TxProof {
    type Input = GenerationInputs;
    type Output = ();

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let _span = TxProofSpan::new(&input);

        if self.save_inputs_on_error {
            evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                input.clone(),
            )
            .map_err(|err| {
                if let Err(write_err) = save_inputs_to_disk(
                    format!(
                        "b{}_txn_{}_input.log",
                        input.block_metadata.block_number, input.txn_number_before
                    ),
                    input,
                ) {
                    error!("Failed to save txn proof input to disk: {:?}", write_err);
                }

                FatalError::from_anyhow(err, FatalStrategy::Terminate)
            })?;
        } else {
            evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                input,
            )
            .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate))?;
        }

        Ok(())
    }
}

/// RAII struct to measure the time taken by a transaction proof.
///
/// - When created, it starts a span with the transaction proof id.
/// - When dropped, it logs the time taken by the transaction proof.
struct TxProofSpan {
    _span: tracing::span::EnteredSpan,
    start: Instant,
    descriptor: String,
}

impl TxProofSpan {
    /// Get a unique id for the transaction proof.
    fn get_id(ir: &GenerationInputs) -> String {
        format!(
            "b{} - {}",
            ir.block_metadata.block_number, ir.txn_number_before
        )
    }

    /// Get a textual descriptor for the transaction proof.
    ///
    /// Either the hex-encoded hash of the transaction or "Dummy" if the
    /// transaction is not present.
    fn get_descriptor(ir: &GenerationInputs) -> String {
        ir.signed_txn
            .as_ref()
            .map(|txn| format!("{:x}", keccak(txn)))
            .unwrap_or_else(|| "Dummy".to_string())
    }

    /// Create a new transaction proof span.
    ///
    /// When dropped, it logs the time taken by the transaction proof.
    fn new(ir: &GenerationInputs) -> Self {
        let id = Self::get_id(ir);
        let span = info_span!("p_gen", id).entered();
        let start = Instant::now();
        let descriptor = Self::get_descriptor(ir);
        Self {
            _span: span,
            start,
            descriptor,
        }
    }
}

impl Drop for TxProofSpan {
    fn drop(&mut self) {
        event!(
            Level::INFO,
            "txn proof ({}) took {:?}",
            self.descriptor,
            self.start.elapsed()
        );
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct AggProof {
    pub save_inputs_on_error: bool,
}

fn get_agg_proof_public_values(elem: AggregatableProof) -> PublicValues {
    match elem {
        AggregatableProof::Txn(info) => info.p_vals,
        AggregatableProof::Agg(info) => info.p_vals,
    }
}

impl Monoid for AggProof {
    type Elem = AggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let result = generate_agg_proof(p_state(), &a, &b).map_err(|e| {
            if self.save_inputs_on_error {
                let pv = vec![
                    get_agg_proof_public_values(a),
                    get_agg_proof_public_values(b),
                ];
                if let Err(write_err) = save_inputs_to_disk(
                    format!(
                        "b{}_agg_lhs_rhs_inputs.log",
                        pv[0].block_metadata.block_number
                    ),
                    pv,
                ) {
                    error!("Failed to save agg proof inputs to disk: {:?}", write_err);
                }
            }

            FatalError::from(e)
        })?;

        Ok(result.into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct BlockProof {
    pub prev: Option<GeneratedBlockProof>,
    pub save_inputs_on_error: bool,
}

impl Operation for BlockProof {
    type Input = GeneratedAggProof;
    type Output = GeneratedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(
            generate_block_proof(p_state(), self.prev.as_ref(), &input).map_err(|e| {
                if self.save_inputs_on_error {
                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "b{}_block_input.log",
                            input.p_vals.block_metadata.block_number
                        ),
                        input.p_vals,
                    ) {
                        error!("Failed to save block proof input to disk: {:?}", write_err);
                    }
                }

                FatalError::from(e)
            })?,
        )
    }
}
