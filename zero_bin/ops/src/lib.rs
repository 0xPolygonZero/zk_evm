#[cfg(any(
    all(feature = "cdk_erigon", feature = "polygon_pos"),
    all(feature = "cdk_erigon", feature = "eth_mainnet"),
    all(feature = "polygon_pos", feature = "eth_mainnet"),
    not(any(
        feature = "cdk_erigon",
        feature = "eth_mainnet",
        feature = "polygon_pos"
    ))
))]
compile_error!("Only a single network feature should be enabled at a time!");

use std::time::Instant;

use evm_arithmetization::generation::TrimmedGenerationInputs;
use evm_arithmetization::proof::PublicValues;
use evm_arithmetization::{prover::testing::simulate_execution_all_segments, GenerationInputs};
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use proof_gen::types::Field;
use proof_gen::{
    proof_gen::{generate_block_proof, generate_segment_agg_proof, generate_transaction_agg_proof},
    proof_types::{
        BatchAggregatableProof, GeneratedBlockProof, GeneratedTxnAggProof, SegmentAggregatableProof,
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;
use tracing::{event, info_span, Level};
use zero_bin_common::{debug_utils::save_inputs_to_disk, prover_state::p_state};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProof {
    pub save_inputs_on_error: bool,
}

impl Operation for SegmentProof {
    type Input = evm_arithmetization::AllData;
    type Output = proof_gen::proof_types::SegmentAggregatableProof;

    fn execute(&self, all_data: Self::Input) -> Result<Self::Output> {
        let all_data =
            all_data.map_err(|err| FatalError::from_str(&err.0, FatalStrategy::Terminate))?;

        let input = all_data.0.clone();
        let segment_index = all_data.1.segment_index();
        let _span = SegmentProofSpan::new(&input, all_data.1.segment_index());
        let proof = if self.save_inputs_on_error {
            zero_bin_common::prover_state::p_manager()
                .generate_segment_proof(all_data)
                .map_err(|err| {
                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "b{}_txns_{}..{}-({})_input.json",
                            input.block_metadata.block_number,
                            input.txn_number_before,
                            input.txn_number_before + input.txn_hashes.len(),
                            segment_index
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

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProofTestOnly {
    pub save_inputs_on_error: bool,
}

impl Operation for SegmentProofTestOnly {
    type Input = (GenerationInputs, usize);
    type Output = ();

    fn execute(&self, inputs: Self::Input) -> Result<Self::Output> {
        if self.save_inputs_on_error {
            simulate_execution_all_segments::<Field>(inputs.0.clone(), inputs.1).map_err(|err| {
                if let Err(write_err) = save_inputs_to_disk(
                    format!(
                        "b{}_txns_{}..{}_input.json",
                        inputs.0.block_metadata.block_number,
                        inputs.0.txn_number_before,
                        inputs.0.txn_number_before + inputs.0.signed_txns.len(),
                    ),
                    inputs.0,
                ) {
                    error!("Failed to save txn proof input to disk: {:?}", write_err);
                }

                FatalError::from_anyhow(err, FatalStrategy::Terminate)
            })?
        } else {
            simulate_execution_all_segments::<Field>(inputs.0, inputs.1)
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
    fn get_id(ir: &TrimmedGenerationInputs, segment_index: usize) -> String {
        if ir.txn_hashes.len() == 1 {
            format!(
                "b{} - {} ({})",
                ir.block_metadata.block_number, ir.txn_number_before, segment_index
            )
        } else {
            format!(
                "b{} - {}_{} ({})",
                ir.block_metadata.block_number,
                ir.txn_number_before,
                ir.txn_number_before + ir.txn_hashes.len(),
                segment_index
            )
        }
    }

    /// Get a textual descriptor for the transaction proof.
    ///
    /// Either the first 8 characters of the hex-encoded hash of the first and
    /// last transactions, or "Dummy" if there is no transaction.
    fn get_descriptor(ir: &TrimmedGenerationInputs) -> String {
        if ir.txn_hashes.is_empty() {
            "Dummy".to_string()
        } else if ir.txn_hashes.len() == 1 {
            format!("{:x?}", ir.txn_hashes[0])
        } else {
            let first_encoding = u64::from_be_bytes(ir.txn_hashes[0].0[0..8].try_into().unwrap());
            let last_encoding = u64::from_be_bytes(
                ir.txn_hashes
                    .last()
                    .expect("We have at least 2 transactions.")
                    .0[0..8]
                    .try_into()
                    .unwrap(),
            );

            format!("[0x{:x?}..0x{:x?}]", first_encoding, last_encoding)
        }
    }

    /// Create a new transaction proof span.
    ///
    /// When dropped, it logs the time taken by the transaction proof.
    fn new(ir: &TrimmedGenerationInputs, segment_index: usize) -> Self {
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
pub struct BatchAggProof {
    pub save_inputs_on_error: bool,
}
fn get_agg_proof_public_values(elem: BatchAggregatableProof) -> PublicValues {
    match elem {
        BatchAggregatableProof::Segment(info) => info.p_vals,
        BatchAggregatableProof::Txn(info) => info.p_vals,
        BatchAggregatableProof::Agg(info) => info.p_vals,
    }
}

impl Monoid for BatchAggProof {
    type Elem = BatchAggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let lhs = match a {
            BatchAggregatableProof::Segment(segment) => BatchAggregatableProof::from(
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
            BatchAggregatableProof::Segment(segment) => BatchAggregatableProof::from(
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
                        "b{}_agg_lhs_rhs_inputs.json",
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
                            "b{}_block_input.json",
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
