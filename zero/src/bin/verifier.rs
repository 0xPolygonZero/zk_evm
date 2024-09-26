zk_evm_common::check_chain_features!();

use std::fs::File;

use anyhow::{Context, Result};
use clap::Parser;
use dotenvy::dotenv;
use evm_arithmetization::fixed_recursive_verifier::extract_two_to_one_block_hash;
use serde_json::Deserializer;
use tracing::{error, info, warn};
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
                    .context("Failed to verify block proof")
                    .inspect_err(|e| error!("{e:?}"))
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
                    .context("Failed to verify wrapped block proof")
                    .inspect_err(|e| error!("{e:?}"))
                    .is_ok()
            }) {
                info!("All proofs verified successfully!");
            };
        }
        cli::Command::AggBlock => {
            let input_proofs: Vec<GeneratedAggBlockProof> = serde_path_to_error::deserialize(des)?;

            if input_proofs.into_iter().all(|wrapped_proof| {
                // Assert consistency of the sequence of Public Values.
                //
                // This is not needed for proof verification, but allows to *trust*
                // that the public info being attached in the clear are actually what
                // was used internally when generating this proof, for external use.
                let pis_match = if extract_two_to_one_block_hash(&wrapped_proof.intern.public_inputs) != &wrapped_proof.p_vals.hash().elements {
                    warn!("The sequence of Public Values attached to this proof does not match the public inputs hash.");
                    false
                } else {
                    true
                };

                verifier
                    .verify_block_aggreg(&wrapped_proof.intern)
                    .context("Failed to verify aggregated block proof")
                    .inspect_err(|e| error!("{e:?}"))
                    .is_ok() && pis_match
            }) {
                info!("All proofs verified successfully!");
            };
        }
    };

    Ok(())
}
