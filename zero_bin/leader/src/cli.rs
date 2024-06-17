use std::path::PathBuf;

use alloy::transports::http::reqwest::Url;
use clap::{Parser, Subcommand, ValueHint};
use common::prover_state::cli::CliProverStateConfig;

/// zero-bin leader config
#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    #[clap(flatten)]
    pub(crate) paladin: paladin::config::Config,

    // Note this is only relevant for the leader when running in in-memory
    // mode.
    #[clap(flatten)]
    pub(crate) prover_state_config: CliProverStateConfig,
}

#[derive(Subcommand, Clone)]
pub(crate) enum Command {
    /// Reads input from stdin and writes output to stdout.
    Stdio {
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
        /// If true, save the public inputs to disk on error.
        #[arg(short, long, default_value_t = false)]
        save_inputs_on_error: bool,
    },
    /// Reads input from a Jerigon node and writes output to stdout.
    Jerigon {
        // The Jerigon RPC URL.
        #[arg(long, short = 'u', value_hint = ValueHint::Url)]
        rpc_url: Url,
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
        /// If true, save the public inputs to disk on error.
        #[arg(short, long, default_value_t = false)]
        save_inputs_on_error: bool,
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
    /// Reads input from a native node and writes output to stdout.
    Native {
        // The native RPC URL.
        #[arg(long, short = 'u', value_hint = ValueHint::Url)]
        rpc_url: Url,
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
        /// If true, save the public inputs to disk on error.
        #[arg(short, long, default_value_t = false)]
        save_inputs_on_error: bool,
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
        /// If true, save the public inputs to disk on error.
        #[arg(short, long, default_value_t = false)]
        save_inputs_on_error: bool,
    },
}
