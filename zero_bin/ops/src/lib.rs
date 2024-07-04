use std::time::Instant;

use evm_arithmetization::{proof::PublicValues, GenerationInputs};
use keccak_hash::keccak;
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use proof_gen::{
    proof_gen::{generate_block_proof, generate_segment_agg_proof, generate_transaction_agg_proof},
    proof_types::{
        GeneratedBlockProof, GeneratedTxnAggProof, SegmentAggregatableProof, TxnAggregatableProof,
    },
};
use serde::{Deserialize, Serialize};
use trace_decoder::types::AllData;
use tracing::{error, event, info_span, Level};
use zero_bin_common::{debug_utils::save_inputs_to_disk, prover_state::p_state};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProof {
    pub save_inputs_on_error: bool,
}

#[cfg(not(feature = "test_only"))]
impl Operation for SegmentProof {
    type Input = AllData;
    type Output = proof_gen::proof_types::SegmentAggregatableProof;

    fn execute(&self, all_data: Self::Input) -> Result<Self::Output> {
        let input = all_data.0.clone();
        let _span = SegmentProofSpan::new(&input, all_data.1.segment_index());
        let proof = if self.save_inputs_on_error {
            zero_bin_common::prover_state::p_manager()
                .generate_segment_proof(all_data)
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
            zero_bin_common::prover_state::p_manager()
                .generate_segment_proof(all_data)
                .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate))?
        };

        Ok(proof.into())
    }
}

#[cfg(feature = "test_only")]
impl Operation for SegmentProof {
    type Input = AllData;
    type Output = ();

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let gen_input = input.0;
        let _span = SegmentProofSpan::new(&gen_input, input.1.segment_index());

        if self.save_inputs_on_error {
            evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                gen_input.clone(),
            )
            .map_err(|err| {
                if let Err(write_err) = save_inputs_to_disk(
                    format!(
                        "b{}_txn_{}_input.log",
                        gen_input.block_metadata.block_number, gen_input.txn_number_before
                    ),
                    gen_input,
                ) {
                    error!("Failed to save txn proof input to disk: {:?}", write_err);
                }

                FatalError::from_anyhow(err, FatalStrategy::Terminate)
            })?;
        } else {
            evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                gen_input.clone(),
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
struct SegmentProofSpan {
    _span: tracing::span::EnteredSpan,
    start: Instant,
    descriptor: String,
}

impl SegmentProofSpan {
    /// Get a unique id for the transaction proof.
    fn get_id(ir: &GenerationInputs, segment_index: usize) -> String {
        format!(
            "b{} - {}_{} ({})",
            ir.block_metadata.block_number,
            ir.txn_number_before,
            ir.txn_number_before + ir.signed_txns.len(),
            segment_index
        )
    }

    /// Get a textual descriptor for the transaction proof.
    ///
    /// Either the hex-encoded hash of the transaction or "Dummy" if the
    /// transaction is not present.
    fn get_descriptor(ir: &GenerationInputs) -> String {
        if ir.signed_txns.is_empty() {
            "Dummy".to_string()
        } else {
            format!(
                "{:x?}",
                ir.signed_txns
                    .iter()
                    .map(|txn| keccak(txn.clone()))
                    .collect::<Vec<_>>()
            )
        }
    }

    /// Create a new transaction proof span.
    ///
    /// When dropped, it logs the time taken by the transaction proof.
    fn new(ir: &GenerationInputs, segment_index: usize) -> Self {
        let id = Self::get_id(ir, segment_index);
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

impl Drop for SegmentProofSpan {
    fn drop(&mut self) {
        event!(
            Level::INFO,
            "segment proof ({}) took {:?}",
            self.descriptor,
            self.start.elapsed()
        );
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentAggProof {
    pub save_inputs_on_error: bool,
}

fn get_seg_agg_proof_public_values(elem: SegmentAggregatableProof) -> PublicValues {
    match elem {
        SegmentAggregatableProof::Seg(info) => info.p_vals,
        SegmentAggregatableProof::Agg(info) => info.p_vals,
    }
}

impl Monoid for SegmentAggProof {
    type Elem = SegmentAggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let result = generate_segment_agg_proof(p_state(), &a, &b, false).map_err(|e| {
            if self.save_inputs_on_error {
                let pv = vec![
                    get_seg_agg_proof_public_values(a),
                    get_seg_agg_proof_public_values(b),
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
pub struct TxnAggProof {
    pub save_inputs_on_error: bool,
}
fn get_agg_proof_public_values(elem: TxnAggregatableProof) -> PublicValues {
    match elem {
        TxnAggregatableProof::Segment(info) => info.p_vals,
        TxnAggregatableProof::Txn(info) => info.p_vals,
        TxnAggregatableProof::Agg(info) => info.p_vals,
    }
}

impl Monoid for TxnAggProof {
    type Elem = TxnAggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let lhs = match a {
            TxnAggregatableProof::Segment(segment) => TxnAggregatableProof::from(
                generate_segment_agg_proof(
                    p_state(),
                    &SegmentAggregatableProof::from(segment.clone()),
                    &SegmentAggregatableProof::from(segment),
                    true,
                )
                .map_err(FatalError::from)?,
            ),
            _ => a,
        };

        let rhs = match b {
            TxnAggregatableProof::Segment(segment) => TxnAggregatableProof::from(
                generate_segment_agg_proof(
                    p_state(),
                    &SegmentAggregatableProof::from(segment.clone()),
                    &SegmentAggregatableProof::from(segment),
                    true,
                )
                .map_err(FatalError::from)?,
            ),
            _ => b,
        };

        let result = generate_transaction_agg_proof(p_state(), &lhs, &rhs).map_err(|e| {
            if self.save_inputs_on_error {
                let pv = vec![
                    get_agg_proof_public_values(lhs),
                    get_agg_proof_public_values(rhs),
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
    type Input = GeneratedTxnAggProof;
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
