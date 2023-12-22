use std::path::PathBuf;

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

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Reads input from stdin and writes output to stdout.
    Stdio {
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
    },
    /// Reads input from a Jerigon node and writes output to stdout.
    Jerigon {
        // The Jerigon RPC URL.
        #[arg(long, short = 'u', value_hint = ValueHint::Url)]
        rpc_url: String,
        /// The block number for which to generate a proof.
        #[arg(short, long)]
        block_number: u64,
        /// The checkpoint block number.
        #[arg(short, long, default_value_t = 0)]
        checkpoint_block_number: u64,
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
        /// If provided, write the generated proof to this file instead of
        /// stdout.
        #[arg(long, short = 'o', value_hint = ValueHint::FilePath)]
        proof_output_path: Option<PathBuf>,
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
