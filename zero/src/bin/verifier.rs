zk_evm_common::check_chain_features!();

use std::fs::File;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use serde_json::Deserializer;
use tracing::info;
use zero::proof_types::GeneratedBlockProof;
use zero::prover_state::persistence::set_circuit_cache_dir_env_if_not_set;

use self::verifier::*;
mod verifier {
    pub mod cli;
    pub mod init;
}

fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    set_circuit_cache_dir_env_if_not_set()?;

    let args = cli::Cli::parse();

    let file = File::open(args.file_path)?;
    let des = &mut Deserializer::from_reader(&file);
    let input_proofs: Vec<GeneratedBlockProof> = serde_path_to_error::deserialize(des)?;

    let verifier = args
        .prover_state_config
        .into_prover_state_manager()
        .verifier(args.use_test_config)?;

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
