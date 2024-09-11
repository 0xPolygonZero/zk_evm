#[cfg(any(
    all(feature = "cdk_erigon", feature = "polygon_pos"),
    all(feature = "cdk_erigon", feature = "eth_mainnet"),
    all(feature = "polygon_pos", feature = "eth_mainnet"),
    not(any(
        feature = "cdk_erigon",
        feature = "eth_mainnet",
        feature = "polygon_pos"
    ))
))]
compile_error!("One and only one of the feature chains `cdk_erigon`, `polygon_pos` or `eth_mainnet` must be selected");

use std::env;
use std::fs::File;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use proof_gen::proof_types::GeneratedBlockProof;
use serde_json::Deserializer;
use tracing::info;
use zero_bin_common::{
    prover_state::persistence::{set_circuit_cache_dir_env_if_not_set, CIRCUIT_VERSION},
    version,
};

mod cli;
mod init;

fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    set_circuit_cache_dir_env_if_not_set()?;

    let args: Vec<String> = env::args().collect();
    if args.contains(&"--version".to_string()) {
        version::print_version(
            CIRCUIT_VERSION.as_str(),
            env!("VERGEN_RUSTC_COMMIT_HASH"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        );
        return Ok(());
    }

    let args = cli::Cli::parse();

    let file = File::open(args.file_path)?;
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
