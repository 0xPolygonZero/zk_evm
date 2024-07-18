//! This module contains a lot of the important input structs
use serde::{Deserialize, Serialize};
use zero_bin_common::block_interval::BlockInterval;

use crate::{benchmarking::BenchmarkOutputConfig, fetch::Checkpoint};

/// The source of Blocks to produce the [prover::ProverInput].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSource {
    /// Utilize the RPC function provided by ZeroBin to get the
    /// [prover::ProverInput]
    ZeroBinRpc {
        /// The url of the RPC
        rpc_url: String,
    },
}

unsafe impl Send for BlockSource {}

use crate::proofout::ProofOutputMethod;

/// The input for starting the many-blocks proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveBlocksInput {
    /// The name of the run
    run_name: Option<String>,
    /// The block interval
    ///
    /// See [BlockInterval::new] to see the acceptable [String] representations
    /// for the [BlockInterval]
    block_interval: String,
    /// The checkpoint block number.  If not provided, will be the
    /// the block before the current block number, or
    /// [Checkpoint::BlockNumberNegativeOffset] set to 1.
    checkpoint: Option<Checkpoint>,
    /// How we source the blocks.
    block_source: BlockSource,
    /// Stores the output of the proofs. If not provided, no proofs will be
    /// stored
    proof_output: Option<ProofOutputMethod>,
    /// Stores the output of the benchmark.  If not provided, no benchmarking
    /// stats will be stored
    benchmark_output: Option<BenchmarkOutputConfig>,
    /// Whether or not we should forward the previous proof to the next proof.
    ///
    /// NOTE: There may be some problems if set to true.  Default is false.
    forward_prev: Option<bool>,
}

unsafe impl Send for ProveBlocksInput {}

impl ProveBlocksInput {
    pub fn get_block_interval(&self) -> Result<BlockInterval, anyhow::Error> {
        BlockInterval::new(&self.block_interval)
    }

    #[inline]
    pub fn get_proof_output(&self) -> &Option<ProofOutputMethod> {
        &self.proof_output
    }

    #[inline]
    pub fn get_benchmark_output(&self) -> &Option<BenchmarkOutputConfig> {
        &self.benchmark_output
    }

    #[inline]
    pub fn get_checkpoint(&self) -> &Option<Checkpoint> {
        &self.checkpoint
    }

    #[inline]
    pub fn get_blocksource(&self) -> &BlockSource {
        &self.block_source
    }

    pub fn get_expected_number_proofs(&self) -> Option<u64> {
        match self.get_block_interval() {
            // Ranges should be determined by start and end
            Ok(BlockInterval::Range(range)) => Some(range.end - range.start),
            // Single block should be 1
            Ok(BlockInterval::SingleBlockId(_)) => Some(1),
            // Nothing, then None
            _ => None,
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
