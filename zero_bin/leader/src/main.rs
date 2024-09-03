use std::{env, io};
use std::{fs::File, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use cli::Command;
use client::RpcParams;
use dotenvy::dotenv;
use ops::register;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use prover::ProverConfig;
use tracing::{info, warn};
use zero_bin_common::{
    block_interval::BlockInterval, proof_runtime::ProofRuntime,
    prover_state::persistence::set_circuit_cache_dir_env_if_not_set,
};
use zero_bin_common::{prover_state::persistence::CIRCUIT_VERSION, version};

use crate::client::{client_main, ProofParams};

mod cli;
mod client;
mod http;
mod init;
mod stdio;

fn get_previous_proof(path: Option<PathBuf>) -> Result<Option<GeneratedBlockProof>> {
    if path.is_none() {
        return Ok(None);
    }

    let path = path.unwrap();
    let file = File::open(path)?;
    let des = &mut serde_json::Deserializer::from_reader(&file);
    let proof: GeneratedBlockProof = serde_path_to_error::deserialize(des)?;
    Ok(Some(proof))
}

const SEGMENT_PROOF_ROUTING_KEY: &str = "segment_proof";
const BLOCK_PROOF_ROUTING_KEY: &str = "block_proof";
const DEFAULT_ROUTING_KEY: &str = paladin::runtime::DEFAULT_ROUTING_KEY;

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenvy_vars_if_present();
    set_circuit_cache_dir_env_if_not_set()?;
    init::tracing();

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

    let mut block_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    let mut segment_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    if args.worker_run_mode == cli::WorkerRunMode::Split {
        // If we're running in split mode, we need to set the routing key for the
        // block proof and segment proof.
        info!("Workers running in split mode");
        block_proof_routing_key = BLOCK_PROOF_ROUTING_KEY.to_string();
        segment_proof_routing_key = SEGMENT_PROOF_ROUTING_KEY.to_string();
    }

    let mut block_proof_paladin_args = args.paladin.clone();
    block_proof_paladin_args.task_bus_routing_key = Some(block_proof_routing_key);

    let mut segment_proof_paladin_args = args.paladin.clone();
    segment_proof_paladin_args.task_bus_routing_key = Some(segment_proof_routing_key);

    let block_proof_runtime = Runtime::from_config(&block_proof_paladin_args, register()).await?;
    let segment_proof_runtime =
        Runtime::from_config(&segment_proof_paladin_args, register()).await?;

    let prover_config: ProverConfig = args.prover_config.into();

    // If not in test_only mode and running in emulation mode, we'll need to
    // initialize the prover state here.
    if !prover_config.test_only {
        if let paladin::config::Runtime::InMemory = args.paladin.runtime {
            args.prover_state_config
                .into_prover_state_manager()
                .initialize()?;
        }
    }

    let proof_runtime = ProofRuntime {
        block_proof_runtime,
        segment_proof_runtime,
    };

    match args.command {
        Command::Clean => zero_bin_common::prover_state::persistence::delete_all()?,
        Command::Stdio { previous_proof } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            stdio::stdio_main(proof_runtime, previous_proof, prover_config).await?;
        }
        Command::Http { port, output_dir } => {
            // check if output_dir exists, is a directory, and is writable
            let output_dir_metadata = std::fs::metadata(&output_dir);
            if output_dir_metadata.is_err() {
                // Create output directory
                std::fs::create_dir(&output_dir)?;
            } else if !output_dir.is_dir() || output_dir_metadata?.permissions().readonly() {
                panic!("output-dir is not a writable directory");
            }

            http::http_main(proof_runtime, port, output_dir, prover_config).await?;
        }
        Command::Rpc {
            rpc_url,
            rpc_type,
            block_interval,
            checkpoint_block_number,
            previous_proof,
            proof_output_dir,
            block_time,
            keep_intermediate_proofs,
            backoff,
            max_retries,
        } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            let mut block_interval = BlockInterval::new(&block_interval)?;

            if let BlockInterval::FollowFrom {
                start_block: _,
                block_time: ref mut block_time_opt,
            } = block_interval
            {
                *block_time_opt = Some(block_time);
            }

            info!("Proving interval {block_interval}");
            client_main(
                proof_runtime,
                RpcParams {
                    rpc_url,
                    rpc_type,
                    backoff,
                    max_retries,
                },
                block_interval,
                ProofParams {
                    checkpoint_block_number,
                    previous_proof,
                    proof_output_dir,
                    prover_config,
                    keep_intermediate_proofs,
                },
            )
            .await?;
        }
    }

    Ok(())
}

/// Attempt to load in the local `.env` if present and set any environment
/// variables specified inside of it.
///
/// To keep things simple, any IO error we will treat as the file not existing
/// and continue moving on without the `env` variables set.
fn load_dotenvy_vars_if_present() {
    match dotenv() {
        Ok(_) | Err(dotenvy::Error::Io(io::Error { .. })) => (),
        Err(e) => warn!("Found local `.env` file but was unable to parse it! (err: {e})",),
    }
}
