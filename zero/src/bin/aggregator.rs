zk_evm_common::check_chain_features!();

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use cli::Command;
use paladin::directive::{Directive, IndexedStream};
use paladin::runtime::Runtime;
use tracing::info;
use zero::env::load_dotenvy_vars_if_present;
use zero::ops::{register, BlockAggProof, WrappedBlockProof};
use zero::proof_types::{
    AggregatableBlockProof, GeneratedAggBlockProof, GeneratedBlockProof, GeneratedWrappedBlockProof,
};
use zero::prover::ProverConfig;
use zero::prover_state::persistence::set_circuit_cache_dir_env_if_not_set;

use self::aggregator::*;
mod aggregator {
    pub mod cli;
    pub mod stdio;
}

pub async fn wrap(
    proof: GeneratedBlockProof,
    runtime: Arc<Runtime>,
    prover_config: Arc<ProverConfig>,
) -> Result<GeneratedWrappedBlockProof> {
    let block_number = proof.b_height;
    info!("Wrapping block proof at height {block_number}");

    let block_proof = paladin::directive::Literal(proof)
        .map(&WrappedBlockProof {
            save_inputs_on_error: prover_config.save_inputs_on_error,
        })
        .run(&runtime)
        .await?;

    info!("Successfully wrapped proof for block {block_number}");
    Ok(block_proof.0)
}

pub async fn aggregate(
    proofs: Vec<AggregatableBlockProof>,
    runtime: Arc<Runtime>,
    prover_config: Arc<ProverConfig>,
) -> Result<GeneratedAggBlockProof> {
    info!("Aggregating wrapped block proofs");

    let agg_proof = IndexedStream::from(proofs)
        .fold(&BlockAggProof {
            save_inputs_on_error: prover_config.save_inputs_on_error,
        })
        .run(&runtime)
        .await?;

    info!("Successfully aggregated block proofs");

    Ok(agg_proof.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    load_dotenvy_vars_if_present();
    set_circuit_cache_dir_env_if_not_set()?;
    zero::tracing::init();

    let args = cli::Cli::parse();

    if let paladin::config::Runtime::InMemory = args.paladin.runtime {
        args.prover_state_config
            .into_prover_state_manager()
            .initialize()?;
    }

    let runtime = Arc::new(Runtime::from_config(&args.paladin, register()).await?);
    let prover_config: ProverConfig = args.prover_config.into();
    if prover_config.block_pool_size == 0 {
        panic!("block-pool-size must be greater than 0");
    }

    match args.command {
        Command::Stdio {} => {
            if args.wrap {
                stdio::stdio_wrap(runtime, Arc::new(prover_config)).await?
            } else {
                stdio::stdio_aggregate(runtime, Arc::new(prover_config)).await?
            }
        }
        Command::Rpc {} => todo!(), // TODO(Robin): Do we want to support RPC input source?
        Command::Http {} => todo!(), // TODO(Robin): Do we want to support RPC input source?
    }

    Ok(())
}