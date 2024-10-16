zk_evm_common::check_chain_features!();

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use cli::Command;
use client::RpcParams;
use paladin::config::Config;
use paladin::runtime::Runtime;
use tracing::info;
use zero::env::load_dotenvy_vars_if_present;
use zero::prover::{ProofRuntime, ProverConfig};
use zero::{
    block_interval::BlockInterval, prover_state::persistence::set_circuit_cache_dir_env_if_not_set,
};
use zero::{fs::get_previous_proof, ops::register};

use self::leader::*;
use crate::client::{client_main, LeaderConfig};
mod leader {
    pub mod cli;
    pub mod client;
    pub mod http;
    pub mod stdio;
}

const HEAVY_PROOF_ROUTING_KEY: &str = "heavy-proof";
const LIGHT_PROOF_ROUTING_KEY: &str = "light-proof";
const DEFAULT_ROUTING_KEY: &str = paladin::runtime::DEFAULT_ROUTING_KEY;

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenvy_vars_if_present();
    set_circuit_cache_dir_env_if_not_set()?;
    zero::tracing::init();

    let args = cli::Cli::parse();

    if let Command::Clean = args.command {
        return zero::prover_state::persistence::delete_all();
    }

    let mut light_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    let mut heavy_proof_routing_key = DEFAULT_ROUTING_KEY.to_string();
    if args.worker_run_mode == cli::WorkerRunMode::Affinity {
        // If we're running in affinity mode, we need to set the routing key for the
        // heavy proof and light proof.
        info!("Workers running in affinity mode");
        light_proof_routing_key = LIGHT_PROOF_ROUTING_KEY.to_string();
        heavy_proof_routing_key = HEAVY_PROOF_ROUTING_KEY.to_string();
    }

    let light_proof_paladin_args = Config {
        task_bus_routing_key: Some(light_proof_routing_key),
        ..args.paladin.clone()
    };

    let heavy_proof_paladin_args = Config {
        task_bus_routing_key: Some(heavy_proof_routing_key),
        ..args.paladin
    };

    let light_proof = Runtime::from_config(&light_proof_paladin_args, register()).await?;
    let heavy_proof = Runtime::from_config(&heavy_proof_paladin_args, register()).await?;

    let proof_runtime = Arc::new(ProofRuntime {
        light_proof,
        heavy_proof,
    });
    let prover_config: ProverConfig = args.prover_config.into();
    if prover_config.block_pool_size == 0 {
        panic!("block-pool-size must be greater than 0");
    }

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
            jumpdest_src,
            block_interval,
            checkpoint_block_number,
            previous_proof,
            block_time,
            backoff,
            max_retries,
            timeout,
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
                    jumpdest_src,
                    timeout,
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
