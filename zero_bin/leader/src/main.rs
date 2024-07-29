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
use tracing::{info, warn};
use zero_bin_common::block_interval::BlockInterval;
use zero_bin_common::version;

use crate::client::{client_main, ProofParams};

mod cli;
mod client;
mod http;
mod init;
mod stdio;

const EVM_ARITHMETIZATION_PKG_VER: &str = "EVM_ARITHMETIZATION_PKG_VER";

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
    init::tracing();

    if env::var_os(EVM_ARITHMETIZATION_PKG_VER).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                EVM_ARITHMETIZATION_PKG_VER,
                // see version.rs
                env!("EVM_ARITHMETIZATION_PKG_VER"),
            );
        }
    }

    let args = cli::Cli::parse();
    if let paladin::config::Runtime::InMemory = args.paladin.runtime {
        // If running in emulation mode, we'll need to initialize the prover
        // state here.
        args.prover_state_config
            .into_prover_state_manager()
            .initialize()?;
    }

    match args.command {
        Command::Version {} => version::print_version(
            env!("EVM_ARITHMETIZATION_PKG_VER"),
            env!("VERGEN_RUSTC_COMMIT_HASH"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        ),
        Command::Stdio {
            previous_proof,
            save_inputs_on_error,
        } => {
            let runtime = Runtime::from_config(&args.paladin, register()).await?;
            let previous_proof = get_previous_proof(previous_proof)?;
            stdio::stdio_main(runtime, previous_proof, save_inputs_on_error).await?;
        }
        Command::Http {
            port,
            output_dir,
            save_inputs_on_error,
        } => {
            let runtime = Runtime::from_config(&args.paladin, register()).await?;
            // check if output_dir exists, is a directory, and is writable
            let output_dir_metadata = std::fs::metadata(&output_dir);
            if output_dir_metadata.is_err() {
                // Create output directory
                std::fs::create_dir(&output_dir)?;
            } else if !output_dir.is_dir() || output_dir_metadata?.permissions().readonly() {
                panic!("output-dir is not a writable directory");
            }

            http::http_main(runtime, port, output_dir, save_inputs_on_error).await?;
        }
        Command::Rpc {
            rpc_url,
            rpc_type,
            block_interval,
            checkpoint_block_number,
            previous_proof,
            proof_output_dir,
            save_inputs_on_error,
            block_time,
            keep_intermediate_proofs,
            backoff,
            max_retries,
        } => {
            let runtime = Runtime::from_config(&args.paladin, register()).await?;
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
                runtime,
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
                    save_inputs_on_error,
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
