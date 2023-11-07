use std::path::PathBuf;

use clap::{Parser, ValueHint};

#[derive(Parser)]
pub(crate) struct Cli {
    /// The file containing the proof to verify
    #[arg(short, long, value_hint = ValueHint::FilePath)]
    pub(crate) file_path: PathBuf,
}
