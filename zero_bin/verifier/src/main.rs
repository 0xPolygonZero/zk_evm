use std::fs::File;

use anyhow::Result;
use clap::Parser;
use proof_gen::types::PlonkyProofIntern;
use serde_json::Deserializer;

mod cli;
mod init;

fn main() -> Result<()> {
    init::tracing();

    let args = cli::Cli::parse();
    let file = File::open(args.file_path)?;
    let des = &mut Deserializer::from_reader(&file);
    let input: PlonkyProofIntern = serde_path_to_error::deserialize(des)?;

    let verifer = args
        .prover_state_config
        .into_prover_state_manager()
        .verifier()?;

    verifer.verify(&input)?;

    Ok(())
}
