use std::env;
use std::fs::File;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use proof_gen::proof_types::GeneratedBlockProof;
use serde_json::Deserializer;
use tracing::info;
use zero_bin_common::version;

mod cli;
mod init;

use cli::Command;

fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    let args = cli::Cli::parse();

    if let Some(Command::Version {}) = args.command {
        version::print_version(
            env!("EVM_ARITHMETIZATION_PKG_VER"),
            env!("VERGEN_RUSTC_COMMIT_HASH"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        );
        return Ok(());
    }

    let file = File::open(args.file_path.unwrap())?;
    let des = &mut Deserializer::from_reader(&file);
    let input_proofs: Vec<GeneratedBlockProof> = serde_path_to_error::deserialize(des)?;

    let verifier = args
        .prover_state_config
        .into_prover_state_manager()
        .verifier()?;

    if input_proofs.into_iter().all(|block_proof| {
        verifier
            .verify(&block_proof.intern)
            .map_err(|e| {
                info!("Proof verification failed with error: {:?}", e);
            })
            .is_ok()
    }) {
        info!("All proofs verified successfully!");
    };

    Ok(())
}
