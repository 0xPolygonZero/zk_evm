use std::path::PathBuf;

use alloy::transports::http::reqwest::Url;
use clap::{Parser, Subcommand, ValueHint};
use prover::cli::CliProverConfig;
use rpc::RpcType;
use zero_bin_common::prover_state::cli::CliProverStateConfig;

/// zero-bin leader config
#[derive(Parser)]
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
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Deletes all the previously cached circuits.
    Clean,
    /// Reads input from stdin and writes output to stdout.
    Stdio {
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
    },
    /// Reads input from a node rpc and writes output to stdout.
    Rpc {
        // The node RPC URL.
        #[arg(long, short = 'u', value_hint = ValueHint::Url)]
        rpc_url: Url,
        // The node RPC type (jerigon / native).
        #[arg(long, short = 't', default_value = "jerigon")]
        rpc_type: RpcType,
        /// The block interval for which to generate a proof.
        #[arg(long, short = 'i')]
        block_interval: String,
        /// The checkpoint block number.
        #[arg(short, long, default_value_t = 0)]
        checkpoint_block_number: u64,
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
        /// If provided, write the generated proofs to this directory instead of
        /// stdout.
        #[arg(long, short = 'o', value_hint = ValueHint::FilePath)]
        proof_output_dir: Option<PathBuf>,
        /// Network block time in milliseconds. This value is used
        /// to determine the blockchain node polling interval.
        #[arg(short, long, env = "ZERO_BIN_BLOCK_TIME", default_value_t = 2000)]
        block_time: u64,
        /// Keep intermediate proofs. Default action is to
        /// delete them after the final proof is generated.
        #[arg(
            short,
            long,
            env = "ZERO_BIN_KEEP_INTERMEDIATE_PROOFS",
            default_value_t = false
        )]
        keep_intermediate_proofs: bool,
        /// Backoff in milliseconds for request retries
        #[arg(long, default_value_t = 0)]
        backoff: u64,
        /// The maximum number of retries
        #[arg(long, default_value_t = 0)]
        max_retries: u32,
    },
    /// Reads input from HTTP and writes output to a directory.
    Http {
        /// The port on which to listen.
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// The directory to which output should be written.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        output_dir: PathBuf,
    },
}
