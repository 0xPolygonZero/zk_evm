zk_evm_common::check_chain_features!();

use std::fs::File;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use serde_json::Deserializer;
use tracing::info;
use zero::proof_types::{AggregatableBlockProof, GeneratedAggBlockProof, GeneratedBlockProof};
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

    let verifier = args
        .prover_state_config
        .into_prover_state_manager()
        .verifier()?;

    let file = File::open(args.file_path)?;
    let des = &mut Deserializer::from_reader(&file);

    match args.command {
        cli::Command::Block => {
            let input_proofs: Vec<GeneratedBlockProof> = serde_path_to_error::deserialize(des)?;

            if input_proofs.into_iter().all(|block_proof| {
                verifier
                    .verify_block(&block_proof.intern)
                    .map_err(|e| {
                        info!("Block proof verification failed with error: {:?}", e);
                    })
                    .is_ok()
            }) {
                info!("All proofs verified successfully!");
            };
        }
        cli::Command::WrappedBlock => {
            let input_proofs: Vec<AggregatableBlockProof> = serde_path_to_error::deserialize(des)?;

            if input_proofs.into_iter().all(|block_proof| {
                verifier
                    .verify_block_wrapper(block_proof.intern())
                    .map_err(|e| {
                        info!(
                            "Wrapped block proof verification failed with error: {:?}",
                            e
                        );
                    })
                    .is_ok()
            }) {
                info!("All proofs verified successfully!");
            };
        }
        cli::Command::AggBlock => {
            let input_proofs: Vec<GeneratedAggBlockProof> = serde_path_to_error::deserialize(des)?;

            if input_proofs.into_iter().all(|block_proof| {
                verifier
                    .verify_block_aggreg(&block_proof.intern)
                    .map_err(|e| {
                        info!(
                            "Aggregated block proof verification failed with error: {:?}",
                            e
                        );
                    })
                    .is_ok()
            }) {
                info!("All proofs verified successfully!");
            };
        }
    };

    Ok(())
}
