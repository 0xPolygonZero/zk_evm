use std::path::PathBuf;

use clap::{Args, ValueHint};

const HELP_HEADING: &str = "Prover options";

// If not provided, default output path is `./proofs/`.
fn get_default_output_path() -> PathBuf {
    let mut path = std::env::current_dir().unwrap_or_default();
    path.push("proofs");
    path
}

/// Represents the main configuration structure for the runtime.
#[derive(Args, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct CliProverConfig {
    /// The log of the max number of CPU cycles per proof.
    #[arg(short, long, help_heading = HELP_HEADING, default_value_t = 19)]
    max_cpu_len_log: usize,
    /// Number of transactions in a batch to process at once.
    #[arg(short, long, help_heading = HELP_HEADING, default_value_t = 1)]
    batch_size: usize,
    /// If true, save the public inputs to disk on error.
    #[arg(short='i', long, help_heading = HELP_HEADING, default_value_t = false)]
    save_inputs_on_error: bool,
    /// If true, only test the trace decoder and witness generation without
    /// generating a proof.
    #[arg(long, help_heading = HELP_HEADING, default_value_t = false)]
    test_only: bool,
    /// Directory where the generated proofs will be written.
    #[arg(long, short = 'o', value_hint = ValueHint::FilePath, default_value = get_default_output_path().into_os_string())]
    proof_output_dir: PathBuf,
    /// Keep intermediate proofs. Default action is to
    /// delete them after the final proof is generated.
    #[arg(
        short,
        long,
        env = "ZERO_BIN_KEEP_INTERMEDIATE_PROOFS",
        default_value_t = false
    )]
    keep_intermediate_proofs: bool,
    /// Number of blocks in a batch. For every block batch, the prover will
    /// generate one proof file.
    #[arg(long, default_value_t = 8)]
    block_batch_size: usize,
}

impl From<CliProverConfig> for crate::ProverConfig {
    fn from(cli: CliProverConfig) -> Self {
        Self {
            batch_size: cli.batch_size,
            max_cpu_len_log: cli.max_cpu_len_log,
            save_inputs_on_error: cli.save_inputs_on_error,
            test_only: cli.test_only,
            proof_output_dir: cli.proof_output_dir,
            keep_intermediate_proofs: cli.keep_intermediate_proofs,
            block_batch_size: cli.block_batch_size,
        }
    }
}
