//! This module contains everything to prove multiple blocks in either parallel
//! or sequential.

use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use paladin::runtime::Runtime;
use tokio::task::JoinError;
use tracing::{debug, error, info, warn};

use crate::benchmarking::{
    BenchmarkingOutput, BenchmarkingOutputBuildError, BenchmarkingOutputError, BenchmarkingStats,
};
use crate::fetch::{fetch, FetchError};
use crate::input::{ProveBlocksInput, TerminateOn};
use crate::proofout::{ProofOutput, ProofOutputBuildError, ProofOutputError};

//===========================================================================================
// ManyProverError
//===========================================================================================
#[derive(Debug)]
pub enum ManyProverError {
    Fetch(FetchError),
    Proof(anyhow::Error),
    BenchmarkingOutput(BenchmarkingOutputError),
    ProofOutError(ProofOutputError),
    UnsupportedTerminationCondition(TerminateOn),
    ParallelJoinError(JoinError),
    FailedToSendTask(u64),
}

impl From<FetchError> for ManyProverError {
    fn from(value: FetchError) -> Self {
        Self::Fetch(value)
    }
}

impl std::fmt::Display for ManyProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for ManyProverError {}

//===========================================================================================
// ManyProverBuildError
//===========================================================================================

#[derive(Debug)]
pub enum ManyProverBuildError {
    /// An error while preparing the means of outputting benchmark statistics
    BenchmarkingOutput(BenchmarkingOutputBuildError),
    /// An error while preparing the means of outputting the proof output
    ProofOutError(ProofOutputBuildError),
    /// Returned with a description of why the configuration was invalid
    InvalidConfiguration(String),
}

impl std::fmt::Display for ManyProverBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

impl std::error::Error for ManyProverBuildError {}

//===========================================================================================
// ManyProver Object
//===========================================================================================

/// The [ManyProver] struct maintains the state and necessary information
pub struct ManyProver {
    /// The original request
    pub input_request: ProveBlocksInput,
    /// The runtime created to handle the workload distribution
    pub runtime: Arc<Runtime>,
    /// If present, the expected handler for outputing proofs
    pub proof_out: Option<ProofOutput>,
    /// If present, the expected handler for outputting benchmark statistics
    pub benchmark_out: Option<BenchmarkingOutput>,
}

impl ManyProver {
    /// Returns the [ManyProver] object.  This can be used to run many proofs
    /// and gather benchmarking statistics simultaneously.
    pub async fn new(
        input: ProveBlocksInput,
        runtime: Arc<Runtime>,
    ) -> Result<Self, ManyProverBuildError> {
        //=================================================================================
        // Starting messages
        //=================================================================================

        info!("Instansiating a new ManyProver object");

        info!("Input received: {:?}", input);

        //=================================================================================
        // Init & Setup
        //=================================================================================

        debug!("Preparing means of outputting the generated proofs...");
        // get the proof
        let proof_out = match &input.proof_output {
            Some(proof_method) => match ProofOutput::from_method(proof_method) {
                Ok(proof_out) => {
                    info!("Instansiated means of proof output");
                    Some(proof_out)
                }
                Err(err) => {
                    error!("Failed to build proof out");
                    return Err(ManyProverBuildError::ProofOutError(err));
                }
            },
            None => {
                info!("Proof output is disabled, will not output proofs.");
                None
            }
        };

        debug!("Preparing benchmark output...");
        let benchmark_out = match &input.benchmark_output {
            Some(benchmark_config) => {
                match BenchmarkingOutput::from_config(
                    benchmark_config.clone(),
                    input.estimate_expected_number_proofs(),
                )
                .await
                {
                    Ok(benchmark_output) => Some(benchmark_output),
                    Err(err) => {
                        error!("Failed to construct Benchmark Output: {}", err);
                        return Err(ManyProverBuildError::BenchmarkingOutput(err));
                    }
                }
            }
            None => {
                info!("Was not provided means to place benchmarking statistics output...");
                None
            }
        };

        Ok(Self {
            input_request: input,
            runtime,
            proof_out,
            benchmark_out,
        })
    }

    /// Returns true if we are storing the proofs
    pub fn storing_proof(&self) -> bool {
        self.proof_out.is_some()
    }

    /// Returns true if we are storing benchmarks
    pub fn storing_benchmark(&self) -> bool {
        self.benchmark_out.is_some()
    }

    //===========================================================================================
    // Running
    //===========================================================================================

    pub async fn prove_blocks(&mut self) -> Result<(), ManyProverError> {
        info!("Startng to prove blocks");

        info!("Starting fetch");
        let prover_input = fetch(
            self.input_request
                .get_block_interval()
                .map_err(FetchError::ZeroBinRpcFetchError)?,
            &self.input_request.checkpoint,
            &self.input_request.block_source,
        )
        .await?;
        info!("Fetch completed");

        info!("Starting proofs");
        let block_proof_start_time: DateTime<Utc> = Utc::now();
        let block_proofs = match prover_input
            .proverinput
            .prove_and_benchmark(&self.runtime, None, true, None)
            .await
        {
            Ok(block_proofs) => block_proofs,
            Err(err) => return Err(ManyProverError::Proof(err)),
        };
        info!("Finalized benchmarked proofs");

        let mut cumulative_n_txs: u64 = 0;
        let mut cumulative_gas_used: u64 = 0;

        let mut fetch_times = prover_input.fetch_times.iter();

        for (blocknum, maybe_block_proof) in block_proofs.iter() {

            let fetch_time = fetch_times.next();

            let benchmark_block_proof = match maybe_block_proof {
                Some(benchmark_block_proof) => benchmark_block_proof,
                None => {
                    warn!("BLOCK NUM {} DID NOT HAVE A RETURNED VALUE", blocknum);
                    continue;
                }
            };

            cumulative_n_txs += benchmark_block_proof.n_txs;
            cumulative_gas_used += benchmark_block_proof.gas_used;

            let proof_out_time = match &self.proof_out {
                Some(proof_out) => {
                    let proof_out_instant = Instant::now();
                    match proof_out.write(&benchmark_block_proof.proof) {
                        Ok(_) => (),
                        Err(err) => return Err(ManyProverError::ProofOutError(err)),
                    }
                    Some(proof_out_instant.elapsed())
                }
                None => None,
            };

            match &mut self.benchmark_out {
                Some(benchmark_out) => benchmark_out.push(BenchmarkingStats {
                    block_number: benchmark_block_proof.proof.b_height,
                    n_txs: benchmark_block_proof.n_txs,
                    cumulative_n_txs: Some(cumulative_n_txs),
                    fetch_duration: fetch_time.copied(),
                    total_proof_duration: benchmark_block_proof
                        .total_dur
                        .expect("Value is expected"),
                    prep_duration: benchmark_block_proof.prep_dur,
                    proof_out_duration: proof_out_time,
                    agg_wait_duration: benchmark_block_proof.agg_wait_dur,
                    agg_duration: benchmark_block_proof.agg_dur,
                    gas_used: benchmark_block_proof.gas_used,
                    gas_used_per_tx: benchmark_block_proof.gas_used_per_tx.clone(),
                    txproof_duration: benchmark_block_proof.proof_dur,
                    start_time: benchmark_block_proof.start_time,
                    end_time: benchmark_block_proof.end_time,
                    difficulty: benchmark_block_proof.difficulty,
                    cumulative_gas_used: Some(cumulative_gas_used),
                    overall_elapsed_seconds: Some(
                        (benchmark_block_proof.end_time - block_proof_start_time).num_seconds()
                            as u64,
                    ),
                }),
                None => todo!(),
            }
        }

        match &self.benchmark_out {
            Some(benchmark_out) => match benchmark_out.publish().await {
                Ok(_) => (),
                Err(err) => return Err(ManyProverError::BenchmarkingOutput(err)),
            },
            None => (),
        }

        Ok(())
    }
}
