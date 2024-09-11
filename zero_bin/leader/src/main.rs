zk_evm_common::check_chain_features!();

use std::sync::Arc;
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
    block_interval::BlockInterval, prover_state::persistence::set_circuit_cache_dir_env_if_not_set,
};
use zero_bin_common::{prover_state::persistence::CIRCUIT_VERSION, version};

use crate::client::{client_main, LeaderConfig};

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

    if let Command::Clean = args.command {
        return zero_bin_common::prover_state::persistence::delete_all();
    }

    let runtime = Arc::new(Runtime::from_config(&args.paladin, register()).await?);
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

    match args.command {
        Command::Stdio { previous_proof } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            stdio::stdio_main(runtime, previous_proof, Arc::new(prover_config)).await?;
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

            http::http_main(runtime, port, output_dir, Arc::new(prover_config)).await?;
        }
        Command::Rpc {
            rpc_url,
            rpc_type,
            block_interval,
            checkpoint_block_number,
            previous_proof,
            block_time,
            backoff,
            max_retries,
        } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            let block_interval = BlockInterval::new(&block_interval)?;

            info!("Proving interval {block_interval}");
            client_main(
                runtime,
                RpcParams {
                    rpc_url,
                    rpc_type,
                    backoff,
                    max_retries,
                    block_time,
                },
                block_interval,
                LeaderConfig {
                    checkpoint_block_number,
                    previous_proof,
                    prover_config,
                },
            )
            .await?;
        }
        Command::Clean => unreachable!("Flushing has already been handled."),
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
