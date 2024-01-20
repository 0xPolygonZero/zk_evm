use std::path::PathBuf;

use clap::{Parser, ValueHint};
use common::prover_state::cli::CliProverStateConfig;

#[derive(Parser)]
pub(crate) struct Cli {
    /// The file containing the proof to verify
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    pub(crate) file_path: PathBuf,
    /// The prover configuration used to generate the preprocessed circuits
    /// and the verifier state.
    #[clap(flatten)]
    pub(crate) prover_state_config: CliProverStateConfig,
}
