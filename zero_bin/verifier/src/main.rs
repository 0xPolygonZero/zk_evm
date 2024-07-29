use std::env;
use std::fs::File;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use proof_gen::proof_types::GeneratedBlockProof;
use serde_json::Deserializer;
use tracing::info;

mod cli;
mod init;

use cli::Command;

const EVM_ARITH_VER_KEY: &str = "EVM_ARITHMETIZATION_PKG_VER";
const VERGEN_BUILD_TIMESTAMP: &str = "VERGEN_BUILD_TIMESTAMP";
const VERGEN_RUSTC_COMMIT_HASH: &str = "VERGEN_RUSTC_COMMIT_HASH";

fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    let args = cli::Cli::parse();

    if env::var_os(EVM_ARITH_VER_KEY).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                EVM_ARITH_VER_KEY,
                // see build.rs
                env!("EVM_ARITHMETIZATION_PACKAGE_VERSION"),
            );
        }
    }
    if env::var_os(VERGEN_BUILD_TIMESTAMP).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_BUILD_TIMESTAMP,
                // see build.rs
                env!("VERGEN_BUILD_TIMESTAMP"),
            );
        }
    }
    if env::var_os(VERGEN_RUSTC_COMMIT_HASH).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_RUSTC_COMMIT_HASH,
                // see build.rs
                env!("VERGEN_RUSTC_COMMIT_HASH"),
            );
        }
    }

    if let Some(Command::Version {}) = args.command {
        println!(
            "Evm Arithmetization package version: {}",
            env::var(EVM_ARITH_VER_KEY)?
        );
        println!("Build Commit Hash: {}", env::var(VERGEN_RUSTC_COMMIT_HASH)?);
        println!("Build Timestamp: {}", env::var(VERGEN_BUILD_TIMESTAMP)?);
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
