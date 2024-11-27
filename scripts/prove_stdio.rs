use std::{env::set_var, fmt::Display, fs::create_dir_all, path::PathBuf, process::Command};

use alloy::{eips::BlockId, transports::http::reqwest::Url};
use anyhow::{ensure, Ok};
use clap::{arg, Args, ValueEnum, ValueHint};

#[derive(ValueEnum, Copy, Clone)]
enum RunMode {
    /// Dummy proof is generated. Useful for quickly testing decoding and
    /// all other non-proving logic.
    Test,
    /// The proof is generated and verified.
    Verify,
}

#[derive(Args)]
pub struct ProveStdioArgs {
    /// Whether to generate a proof and verify it or not.
    mode: RunMode,
    /// JSON file containing the witness data.
    #[arg(value_hint = ValueHint::DirPath)]
    input_witness_file: PathBuf,
    /// The end of the block range to prove. If None, start_block-1 is used.
    #[arg(long, default_value_t = false)]
    use_test_config: bool,
}

pub fn prove_via_stdio(args: ProveStdioArgs) -> anyhow::Result<()> {
    // Set rustc environment variables.
    set_var("RUST_MIN_STACK", "33554432");
    set_var("RUST_BACKTRACE", "full");
    set_var("RUST_LOG", "info");
    // Script users are running locally, and might benefit from extra perf.
    // See also .cargo/config.toml.
    set_var("RUSTFLAGS", "-C target-cpu=native -Zlinker-features=-lld");

    match args.mode {
        RunMode::Test => {
            let witness_filename = args
                .input_witness_file
                .to_str()
                .ok_or(anyhow::anyhow!("Invalid witness file path"))?;
            if witness_filename.contains("witness_b19807080") {
            } else if witness_filename.contains("witness_b3_b6") {
            } else {
            }
            todo!("Test mode");
        }
        RunMode::Verify => {
            todo!("Verify mode");
        }
    }
    Ok(())
}
