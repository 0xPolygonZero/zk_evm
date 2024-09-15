zk_evm_common::check_chain_features!();

use std::env;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use cli::Command;
use client::RpcParams;
use ops::register;
use paladin::runtime::Runtime;
use prover::ProverConfig;
use tracing::info;
use zero_bin_common::env::load_dotenvy_vars_if_present;
use zero_bin_common::fs::get_previous_proof;
use zero_bin_common::{
    block_interval::BlockInterval, proof_runtime::ProofRuntime,
    prover_state::persistence::set_circuit_cache_dir_env_if_not_set,
};
use zero_bin_common::{prover_state::persistence::CIRCUIT_VERSION, version};

use crate::client::{client_main, LeaderConfig};

mod cli;
mod client;
mod http;
mod stdio;

const HEAVY_PROOF_ROUTING_KEY: &str = "heavy-proof";
const LIGHT_PROOF_ROUTING_KEY: &str = "block-proof";
const DEFAULT_ROUTING_KEY: &str = paladin::runtime::DEFAULT_ROUTING_KEY;

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenvy_vars_if_present();
    set_circuit_cache_dir_env_if_not_set()?;
    zero_bin_common::tracing::init();

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

    let mut light_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    let mut heavy_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    if args.worker_run_mode == cli::WorkerRunMode::Affinity {
        // If we're running in affinity mode, we need to set the routing key for the
        // heavy proof and light proof.
        info!("Workers running in affinity mode");
        light_proof_routing_key = LIGHT_PROOF_ROUTING_KEY.to_string();
        heavy_proof_routing_key = HEAVY_PROOF_ROUTING_KEY.to_string();
    }

    let mut light_proof_paladin_args = args.paladin.clone();
    light_proof_paladin_args.task_bus_routing_key = Some(light_proof_routing_key);

    let mut heavy_proof_paladin_args = args.paladin.clone();
    heavy_proof_paladin_args.task_bus_routing_key = Some(heavy_proof_routing_key);

    let light_proof_runtime = Runtime::from_config(&light_proof_paladin_args, register()).await?;
    let heavy_proof_runtime = Runtime::from_config(&heavy_proof_paladin_args, register()).await?;
    if let Command::Clean = args.command {
        return zero_bin_common::prover_state::persistence::delete_all();
    }

    let proof_runtime = ProofRuntime {
        light_proof_runtime,
        heavy_proof_runtime,
    };

    let proof_runtime = Arc::new(proof_runtime);
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
            stdio::stdio_main(proof_runtime, previous_proof, Arc::new(prover_config)).await?;
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

            http::http_main(proof_runtime, port, output_dir, Arc::new(prover_config)).await?;
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
                proof_runtime,
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
