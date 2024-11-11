use std::path::PathBuf;

use alloy::eips::BlockId;
use alloy::transports::http::reqwest::Url;
use clap::{Parser, Subcommand, ValueEnum, ValueHint};
use zero::prover::cli::CliProverConfig;
use zero::prover_state::cli::CliProverStateConfig;
use zero::rpc::RpcType;

const WORKER_HELP_HEADING: &str = "Worker Config options";

/// zero-bin leader config
#[derive(Parser)]
#[command(version = zero::version(), propagate_version = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    #[clap(flatten)]
    pub(crate) paladin: paladin::config::Config,

    #[clap(flatten)]
    pub(crate) prover_config: CliProverConfig,

    // Note this is only relevant for the leader when running in in-memory
    // mode.
    #[clap(flatten)]
    pub(crate) prover_state_config: CliProverStateConfig,

    // Mode to use for worker for setup (affinity or default)
    #[arg(long = "worker-run-mode", help_heading = WORKER_HELP_HEADING, value_enum, default_value = "default")]
    pub(crate) worker_run_mode: WorkerRunMode,
}

/// Defines the mode for worker setup in terms of job allocation:
///
/// - `Affinity`: Workers are assigned specific types of jobs based on their
///   capabilities, distinguishing between heavy and light jobs.
/// - `Default`: No job distinction is made — any worker can handle any type of
///   job, whether heavy or light.
///
/// This enum allows for flexible worker configuration based on workload needs.
#[derive(ValueEnum, Clone, PartialEq, Debug)]
pub enum WorkerRunMode {
    Affinity,
    Default,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Deletes all the previously cached circuits.
    Clean,
    /// Reads input from stdin and writes output to stdout.
    Stdio {
        /// The previous proof output.
        #[arg(short = 'f', long, env="ZERO_BIN_PREVIOUS_PROOF", value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
    },
    /// Reads input from a node rpc and writes output to stdout.
    Rpc {
        // The node RPC URL.
        #[arg(short = 'u', long, env="ZERO_BIN_RPC_URL", value_hint = ValueHint::Url)]
        rpc_url: Url,
        // The node RPC type (jerigon / native).
        #[arg(
            short = 'T',
            long,
            env = "ZERO_BIN_RPC_TYPE",
            default_value = "jerigon"
        )]
        rpc_type: RpcType,
        /// The start of the block range to prove (inclusive).
        #[arg(short = 's', long, env = "ZERO_BIN_START_BLOCK")]
        start_block: BlockId,
        /// The end of the block range to prove (inclusive).
        /// If not provided, leader will work in dynamic mode from `start_block`
        /// following head of the blockchain.
        #[arg(short = 'e', long, env = "ZERO_BIN_END_BLOCK")]
        end_block: Option<BlockId>,
        /// The checkpoint block.
        #[arg(short, long, env = "ZERO_BIN_CHECKPOINT_BLOCK", default_value = "0")]
        checkpoint_block: BlockId,
        /// The previous proof output.
        #[arg(short = 'f', long, env="ZERO_BIN_PREVIOUS_PROOF", value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
        /// Blockchain network block time in milliseconds. This value is used
        /// to determine the blockchain node polling interval.
        #[arg(short, long, env = "ZERO_BIN_BLOCK_TIME", default_value_t = 2000)]
        block_time: u64,
        /// Backoff in milliseconds for retry requests
        #[arg(long, env = "ZERO_BIN_BACKOFF", default_value_t = 0)]
        backoff: u64,
        /// The maximum number of retries
        #[arg(long, env = "ZERO_BIN_MAX_RETRIES", default_value_t = 0)]
        max_retries: u32,
    },
    /// Reads input from HTTP and writes output to a directory.
    Http {
        /// The port on which to listen.
        #[arg(short, long, env = "ZERO_BIN_PORT", default_value_t = 8080)]
        port: u16,
        /// The directory to which output should be written.
        #[arg(short, long, env="ZERO_BIN_OUTPUT_DIR", value_hint = ValueHint::DirPath)]
        output_dir: PathBuf,
    },
}
