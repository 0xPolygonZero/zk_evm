zk_evm_common::check_chain_features!();

use std::time::Instant;

use anyhow::anyhow;
use evm_arithmetization::fixed_recursive_verifier::ProverOutputData;
use evm_arithmetization::proof::FinalPublicValues;
use evm_arithmetization::{prover::testing::simulate_execution_all_segments, GenerationInputs};
use evm_arithmetization::{Field, HashOrPV, PublicValues, TrimmedGenerationInputs};
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use serde::{Deserialize, Serialize};
use tracing::error;
use tracing::{event, info_span, Level};

use crate::debug_utils::save_tries_to_disk;
use crate::proof_types::{
    AggregatableBlockProof, BatchAggregatableProof, GeneratedAggBlockProof, GeneratedBatchAggProof,
    GeneratedBlockProof, GeneratedSegmentAggProof, GeneratedWrappedBlockProof,
    SegmentAggregatableProof,
};
use crate::prover_state::ProverState;
use crate::{debug_utils::save_inputs_to_disk, prover_state::p_state};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct SegmentProof {
    pub save_inputs_on_error: bool,
}

impl Operation for SegmentProof {
    type Input = evm_arithmetization::AllData;
    type Output = crate::proof_types::SegmentAggregatableProof;

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

        Ok(proof.into())
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
        SegmentAggregatableProof::Seg(info) => info.p_vals,
        SegmentAggregatableProof::Agg(info) => info.p_vals,
    }
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
) -> anyhow::Result<GeneratedSegmentAggProof> {
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
    let agg_output_data = p_state.state.prove_segment_aggregation(
        lhs_child.is_agg(),
        &lhs_prover_output_data,
        rhs_child.is_agg(),
        &rhs_prover_output_data,
    )?;

    let p_vals = agg_output_data.public_values;
    let intern = agg_output_data.proof_with_pis;

    Ok(GeneratedSegmentAggProof { p_vals, intern })
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

            FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
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
                .map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?,
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
                .map_err(|e| FatalError::from_str(&e.to_string(), FatalStrategy::Terminate))?,
            ),
            _ => b,
        };

        let (proof, p_vals) = p_state()
            .state
            .prove_batch_aggregation(
                lhs.is_agg(),
                lhs.intern(),
                lhs.public_values(),
                rhs.is_agg(),
                rhs.intern(),
                rhs.public_values(),
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

        Ok(GeneratedBatchAggProof {
            p_vals,
            intern: proof,
        }
        .into())
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
    type Input = GeneratedBatchAggProof;
    type Output = GeneratedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let b_height = input.p_vals.block_metadata.block_number.low_u64();
        let parent_intern = self.prev.as_ref().map(|p| &p.intern);

        let (b_proof_intern, _) = p_state()
            .state
            .prove_block(parent_intern, &input.intern, input.p_vals.clone())
            .map_err(|e| {
                if self.save_inputs_on_error {
                    if let Err(write_err) =
                        save_inputs_to_disk(format!("b{}_block_input.json", b_height), input.p_vals)
                    {
                        error!("Failed to save block proof input to disk: {:?}", write_err);
                    }
                }

                FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
            })?;

        Ok(GeneratedBlockProof {
            b_height,
            intern: b_proof_intern,
        })
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct WrappedBlockProof {
    pub save_inputs_on_error: bool,
}

impl Operation for WrappedBlockProof {
    type Input = GeneratedBlockProof;
    type Output = GeneratedWrappedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let b_height = input.b_height;
        let p_vals = PublicValues::from_public_inputs(&input.intern.public_inputs);
        let chain_id = p_vals.block_metadata.block_chain_id.low_u64();

        let (b_proof_intern, _) = p_state()
            .state
            .prove_block_wrapper(&input.intern, p_vals.clone())
            .map_err(|e| {
                if self.save_inputs_on_error {
                    if let Err(write_err) =
                        save_inputs_to_disk(format!("b{}_block_input.json", b_height), p_vals)
                    {
                        error!(
                            "Failed to save wrapped block proof input to disk: {:?}",
                            write_err
                        );
                    }
                }

                FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
            })?;

        Ok(GeneratedWrappedBlockProof {
            b_height,
            chain_id,
            intern: b_proof_intern,
        })
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct BlockAggProof {
    pub save_inputs_on_error: bool,
}

fn get_block_agg_proof_public_values(elem: AggregatableBlockProof) -> HashOrPV {
    match elem {
        AggregatableBlockProof::Block(info) => {
            FinalPublicValues::from_public_inputs(&info.intern.public_inputs).into()
        }
        AggregatableBlockProof::Agg(info) => info.p_vals,
    }
}

impl Monoid for BlockAggProof {
    type Elem = AggregatableBlockProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let proof = p_state()
            .state
            .prove_two_to_one_block(a.intern(), a.is_agg(), b.intern(), b.is_agg())
            .map_err(|e| {
                if self.save_inputs_on_error {
                    let pv = vec![
                        get_block_agg_proof_public_values(a.clone()),
                        get_block_agg_proof_public_values(b.clone()),
                    ];

                    if let Err(write_err) = save_inputs_to_disk(
                        format!(
                            "block_agg_{:?}_{:?}_inputs.json",
                            pv[0].hash(),
                            pv[1].hash(),
                        ),
                        pv,
                    ) {
                        error!("Failed to save agg proof inputs to disk: {:?}", write_err);
                    }
                }

                FatalError::from_str(&e.to_string(), FatalStrategy::Terminate)
            })?;

        let p_vals = HashOrPV::Sequence(vec![
            HashOrPV::Hash(a.public_values().hash()),
            HashOrPV::Hash(b.public_values().hash()),
        ]);

        Ok(GeneratedAggBlockProof {
            p_vals,
            intern: proof,
        }
        .into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}
