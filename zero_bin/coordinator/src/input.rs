//! This module contains a lot of the important input structs
use prover::cli::CliProverConfig;
use prover::ProverConfig;
use rpc::RpcType;
use serde::{Deserialize, Serialize};
use zero_bin_common::block_interval::BlockInterval;

use crate::{benchmarking::BenchmarkOutputConfig, fetch::Checkpoint};

pub const MAX_RETRIES_DFLT: usize = 0;
pub const BACKOFF_DFLT: usize = 0;

/// The source of Blocks to produce the [prover::ProverInput].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSource {
    /// Utilize the RPC function provided by ZeroBin to get the
    /// [prover::ProverInput]
    Rpc {
        /// The url of the RPC
        rpc_url: String,
        /// The block interval
        ///
        /// See [BlockInterval::new] to see the acceptable [String]
        /// representations for the [BlockInterval]
        block_interval: String,
        /// The checkpoint block number.  If not provided, will be the
        /// the block before the current block number, or
        /// [Checkpoint::BlockNumberNegativeOffset] set to 1.
        checkpoint: Option<Checkpoint>,
        backoff: Option<u64>,
        max_retries: Option<u32>,
        rpc_type: Option<RpcType>
    },
}

unsafe impl Send for BlockSource {}

use crate::proofout::ProofOutputMethod;

/// The input for starting the many-blocks proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveBlocksInput {
    /// The name of the run
    run_name: Option<String>,
    /// How we source the blocks.
    block_source: BlockSource,
    /// Stores the output of the proofs. If not provided, no proofs will be
    /// stored
    proof_output: Option<ProofOutputMethod>,
    /// Stores the output of the benchmark.  If not provided, no benchmarking
    /// stats will be stored
    benchmark_output: Option<BenchmarkOutputConfig>,
    /// Prover Config
    prover_config: Option<ProverConfig>
}

unsafe impl Send for ProveBlocksInput {}

impl ProveBlocksInput {
    #[inline]
    pub fn get_proof_output(&self) -> &Option<ProofOutputMethod> {
        &self.proof_output
    }

    #[inline]
    pub fn get_prover_config(&self) -> ProverConfig {
        match &self.prover_config {
            Some(prover_config) => prover_config.clone(),
            None => ProverConfig::from(CliProverConfig::default())
        }
    }

    #[inline]
    pub fn get_benchmark_output(&self) -> &Option<BenchmarkOutputConfig> {
        &self.benchmark_output
    }

    #[inline]
    pub fn get_blocksource(&self) -> &BlockSource {
        &self.block_source
    }

    pub fn get_expected_number_proofs(&self) -> Option<u64> {
        match &self.block_source {
            BlockSource::Rpc { rpc_url: _, block_interval, checkpoint: _, backoff: _, max_retries: _, rpc_type: _} => {
                match BlockInterval::new(block_interval.as_ref()) {
                    Ok(BlockInterval::SingleBlockId(_)) => Some(1),
                    Ok(BlockInterval::Range(range)) => Some(range.end - range.start + 1),
                    Ok(_) | Err(_) => None,
                }
            }
        }
    }

    /// Returns the estimated number of proofs that will be generated.
    /// If unable to produce an estimate, returns [None]
    ///
    /// This is largely based on the termination condition ([TerminateOn])
    pub fn estimate_expected_number_proofs(&self) -> Option<u64> {
        self.get_expected_number_proofs()
    }
}
