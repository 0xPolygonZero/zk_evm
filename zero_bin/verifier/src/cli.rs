use std::string;

use clap::{Parser, Subcommand, ValueHint};
use zero_bin_common::prover_state::cli::CliProverStateConfig;

#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,

    /// The file containing the proof to verify
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    pub(crate) file_path: Option<string::String>,
    /// The prover configuration used to generate the preprocessed circuits
    /// and the verifier state.
    #[clap(flatten)]
    pub(crate) prover_state_config: CliProverStateConfig,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Version {},
}
