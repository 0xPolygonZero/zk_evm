zk_evm_common::check_chain_features!();

use std::time::Instant;

use anyhow::anyhow;
use evm_arithmetization::{prover::testing::simulate_execution_all_segments, GenerationInputs};
use evm_arithmetization::{
    Field, ProofWithPublicValues, ProverOutputData, PublicValues, TrimmedGenerationInputs,
};
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use tracing::{event, info_span, Level};

use crate::debug_utils::save_tries_to_disk;
use crate::proof_types::{BatchAggregatableProof, GeneratedBlockProof, SegmentAggregatableProof};
use crate::prover_state::ProverState;
use crate::{debug_utils::save_inputs_to_disk, prover_state::p_state};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProof {
    pub save_inputs_on_error: bool,
}

impl Operation for SegmentProof {
    type Input = evm_arithmetization::AllData;
    type Output = SegmentAggregatableProof;

    fn execute(&self, all_data: Self::Input) -> Result<Self::Output> {
        let all_data =
            all_data.map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?;

        let input = all_data.0.clone();
        let segment_index = all_data.1.segment_index();
        let _span = SegmentProofSpan::new(&input, all_data.1.segment_index());
        let proof = if self.save_inputs_on_error {
            crate::prover_state::p_manager()
                .generate_segment_proof(all_data)
                .map_err(|e| {
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

                    FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
                })?
        } else {
            crate::prover_state::p_manager()
                .generate_segment_proof(all_data)
                .map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?
        };

        Ok(SegmentAggregatableProof::Segment(proof))
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProofTestOnly {
    pub save_inputs_on_error: bool,
    pub save_tries_on_error: bool,
}

impl Operation for SegmentProofTestOnly {
    // The input is a tuple of the batch generation inputs, max_cpu_len_log and
    // batch index.
    type Input = (GenerationInputs, usize, usize);
    type Output = ();

    fn execute(&self, inputs: Self::Input) -> Result<Self::Output> {
        if self.save_inputs_on_error || self.save_tries_on_error {
            simulate_execution_all_segments::<Field>(inputs.0.clone(), inputs.1).map_err(|err| {
                let block_number = inputs.0.block_metadata.block_number.low_u64();
                let batch_index = inputs.2;

                let err = if self.save_tries_on_error {
                    if let Some(ref tries) = err.tries {
                        if let Err(write_err) =
                            save_tries_to_disk(&err.to_string(), block_number, batch_index, tries)
                        {
                            error!("Failed to save tries to disk: {:?}", write_err);
                        }
                    }
                    anyhow!(
                        "block:{} batch:{} error: {}",
                        block_number,
                        batch_index,
                        err.to_string()
                    )
                } else {
                    err.into()
                };

                if self.save_inputs_on_error {
                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "b{}_txns_{}..{}_input.json",
                            block_number,
                            inputs.0.txn_number_before,
                            inputs.0.txn_number_before + inputs.0.signed_txns.len(),
                        ),
                        inputs.0,
                    ) {
                        error!("Failed to save txn proof input to disk: {:?}", write_err);
                    }
                }

                FatalError::from_anyhow(err, FatalStrategy::Terminate)
            })?
        } else {
            simulate_execution_all_segments::<Field>(inputs.0, inputs.1)
                .map_err(|err| FatalError::from_anyhow(err.into(), FatalStrategy::Terminate))?;
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
        SegmentAggregatableProof::Segment(info) => info.proof_with_pvs.public_values,
        SegmentAggregatableProof::Agg(info) => info.proof_with_pvs.public_values,
    }
}

/// Generates an aggregation proof from two child proofs.
///
/// Note that the child proofs may be either transaction or aggregation proofs.
///
/// If a transaction only contains a single segment, this function must still be
/// called to generate a `ProofWithPublicValues`. In that case, you can set
/// `has_dummy` to `true`, and provide an arbitrary proof for the right child.
pub fn generate_segment_agg_proof(
    p_state: &ProverState,
    lhs_child: &SegmentAggregatableProof,
    rhs_child: &SegmentAggregatableProof,
) -> anyhow::Result<ProverOutputData> {
    p_state.state.prove_segment_aggregation(
        lhs_child.as_prover_output_data(),
        rhs_child.as_prover_output_data(),
    )
}

impl Monoid for SegmentAggProof {
    type Elem = SegmentAggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let proof = generate_segment_agg_proof(p_state(), &a, &b).map_err(|e| {
            if self.save_inputs_on_error {
                let pv = vec![
                    get_seg_agg_proof_public_values(a.clone()),
                    get_seg_agg_proof_public_values(b.clone()),
                ];
                save_inputs_to_disk(
                    format!(
                        "b{}_seg_agg_{:?}_lhs_monoid.json",
                        pv[0].block_metadata.block_number, pv[0].extra_block_data.gas_used_before
                    ),
                    a.as_prover_output_data(),
                )
                .unwrap();
                save_inputs_to_disk(
                    format!(
                        "b{}_seg_agg_{:?}_rhs_monoid.json",
                        pv[0].block_metadata.block_number, pv[1].extra_block_data.gas_used_before
                    ),
                    b.as_prover_output_data(),
                )
                .unwrap();

                if let Err(write_err) = save_inputs_to_disk(
                    format!("b{}_seg_agg_inputs.json", pv[0].block_metadata.block_number),
                    pv,
                ) {
                    error!("Failed to save agg proof inputs to disk: {:?}", write_err);
                }

                if b.is_dummy() {
                    warn!("WE SHOULD NEVER HAVE DUMMY SEGMENTS HERE");
                }
            }

            FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
        })?;

        if b.is_dummy() {
            warn!("WE SHOULD NEVER HAVE DUMMY SEGMENTS HERE");
        }

        Ok(SegmentAggregatableProof::Agg(proof))
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
        BatchAggregatableProof::Segment(info) => info.proof_with_pvs.public_values,
        BatchAggregatableProof::SegmentAgg(info) => info.proof_with_pvs.public_values,
        BatchAggregatableProof::BatchAgg(info) => info.public_values,
    }
}

impl Monoid for BatchAggProof {
    type Elem = BatchAggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let lhs = match a {
            BatchAggregatableProof::Segment(segment) => BatchAggregatableProof::SegmentAgg({
                save_inputs_to_disk(
                    format!(
                        "b{}_seg_agg_{:?}_lhs_dummy.json",
                        segment
                            .proof_with_pvs
                            .public_values
                            .block_metadata
                            .block_number,
                        segment
                            .proof_with_pvs
                            .public_values
                            .extra_block_data
                            .gas_used_before
                    ),
                    segment.clone(),
                )
                .unwrap();

                generate_segment_agg_proof(
                    p_state(),
                    &SegmentAggregatableProof::Segment(segment.clone()),
                    &SegmentAggregatableProof::Segment(ProverOutputData {
                        is_dummy: true,
                        ..segment
                    }),
                )
                .map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?
            }),
            _ => a,
        };

        let rhs = match b {
            BatchAggregatableProof::Segment(segment) => BatchAggregatableProof::SegmentAgg({
                save_inputs_to_disk(
                    format!(
                        "b{}_seg_agg_{:?}_rhs_dummy.json",
                        segment
                            .proof_with_pvs
                            .public_values
                            .block_metadata
                            .block_number,
                        segment
                            .proof_with_pvs
                            .public_values
                            .extra_block_data
                            .gas_used_before
                    ),
                    segment.clone(),
                )
                .unwrap();

                generate_segment_agg_proof(
                    p_state(),
                    &SegmentAggregatableProof::Segment(segment.clone()),
                    &SegmentAggregatableProof::Segment(ProverOutputData {
                        is_dummy: true,
                        ..segment
                    }),
                )
                .map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?
            }),
            _ => b,
        };

        let proof = p_state()
            .state
            .prove_batch_aggregation(
                lhs.is_agg(),
                lhs.proof_with_pvs(),
                rhs.is_agg(),
                rhs.proof_with_pvs(),
            )
            .map_err(|e| {
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

                FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
            })?;

        Ok(BatchAggregatableProof::BatchAgg(proof))
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
    type Input = ProofWithPublicValues;
    type Output = GeneratedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let b_height = input.public_values.block_metadata.block_number.low_u64();
        let parent_intern = self.prev.as_ref().map(|p| &p.intern);

        let block_proof = p_state()
            .state
            .prove_block(parent_intern, &input)
            .map_err(|e| {
                if self.save_inputs_on_error {
                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "b{}_block_input.json",
                            input.public_values.block_metadata.block_number
                        ),
                        input.public_values,
                    ) {
                        error!("Failed to save block proof input to disk: {:?}", write_err);
                    }
                }

                FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
            })?;

        Ok(GeneratedBlockProof {
            b_height,
            intern: block_proof.intern,
        })
    }
}
