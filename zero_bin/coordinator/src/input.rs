//! This module contains a lot of the important input structs
use zero_bin_common::block_interval::BlockInterval;
use serde::{Deserialize, Serialize};

use crate::{benchmarking::BenchmarkOutputConfig, fetch::Checkpoint};

/// The means for terminating.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TerminateOn {
    /// Terminate after `num_seconds` seconds after the start of proving blocks.
    ///
    /// Note: The manyprover may continue to operate after the `num_seconds`,
    /// but will not begin a new proof or record any proofs finalized after
    /// being considered terminated.
    ElapsedSeconds {
        /// The number of seconds needed to elapse since the beginning of the
        /// proving process before terminating.
        num_seconds: u64,
    },
    /// Prove until the sum of gas of all the blocks we proved is equal to
    /// `until_gas_sum` amount of gas.
    BlockGasUsed {
        /// Sets the gas
        until_gas_sum: u64,
    },
    /// Terminate once proved the end block, given by the `block_number`
    /// (inclusive)
    EndBlock {
        /// The block number considered to be the end block, inclusive.
        block_number: u64,
    },
}

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

/// The [BlockConcurrencyMode] represents how we handle the block
/// processing.  
///
/// In Sequential mode, we will never send more than
/// one block at a time to the workers, however this may lead to
/// reduced runtime due to unoccupied workers.
///
/// In concurrent mode, we will try to have at most `max_concurrent`
/// blocks with their workloads currently distributed to the
/// workers.
#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy)]
pub enum BlockConcurrencyMode {
    #[default]
    Sequential,
    Parallel {
        max_concurrent: u8,
        /// Represents the maximum number of blocks we can do, if not provided
        /// will have to pick a number on its own
        max_blocks: Option<u64>,
    },
}

impl BlockConcurrencyMode {
    pub fn max_concurrent(&self) -> Option<u8> {
        match self {
            BlockConcurrencyMode::Parallel {
                max_concurrent,
                max_blocks: _,
            } => Some(*max_concurrent),
            _ => None,
        }
    }

    pub fn max_blocks(&self) -> Option<u64> {
        match self {
            Self::Sequential => None,
            Self::Parallel {
                max_concurrent: _,
                max_blocks,
            } => Some(max_blocks.unwrap_or(1000)),
        }
    }
}

use crate::proofout::ProofOutputMethod;

/// The input for starting the many-blocks proving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveBlocksInput {
    /// The name of the run
    pub run_name: Option<String>,
    /// The block interval
    ///
    /// See [BlockInterval::new] to see the acceptable [String] representations
    /// for the [BlockInterval]
    pub block_interval: String,
    /// The checkpoint block number.  If not provided, will be the
    /// the block before the current block number, or
    /// [Checkpoint::BlockNumberNegativeOffset] set to 1.
    pub checkpoint: Option<Checkpoint>,
    /// How we source the blocks.
    pub block_source: BlockSource,
    /// Stores the output of the proofs. If not provided, no proofs will be
    /// stored
    pub proof_output: Option<ProofOutputMethod>,
    /// Stores the output of the benchmark.  If not provided, no benchmarking
    /// stats will be stored
    pub benchmark_output: Option<BenchmarkOutputConfig>,
    /// Whether or not we should forward the previous proof to the next proof.
    ///
    /// NOTE: There may be some problems if set to true.  Default is false.
    pub forward_prev: Option<bool>,
}

impl ProveBlocksInput {
    pub fn get_block_interval(&self) -> Result<BlockInterval, anyhow::Error> {
        BlockInterval::new(&self.block_interval)
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
