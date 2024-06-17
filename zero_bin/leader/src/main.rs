use std::env;
use std::{fs::File, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use cli::Command;
use client::RpcParams;
use common::block_interval::BlockInterval;
use dotenvy::dotenv;
use ops::register;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use tracing::info;

use crate::client::{client_main, ProofParams};
use crate::utils::get_package_version;

mod cli;
mod client;
mod http;
mod init;
mod stdio;
mod utils;

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
    dotenv().ok();
    init::tracing();

    if env::var("EVM_ARITHMETIZATION_PKG_VER").is_err() {
        let pkg_ver = get_package_version("evm_arithmetization")?;
        // Extract the major and minor version parts and append 'x' as the patch version
        if let Some((major_minor, _)) = pkg_ver.as_ref().and_then(|s| s.rsplit_once('.')) {
            let circuits_version = format!("{}.x", major_minor);
            // Set the environment variable for the evm_arithmetization package version
            #[allow(unused_unsafe)]
            unsafe {
                env::set_var("EVM_ARITHMETIZATION_PKG_VER", circuits_version);
            }
        } else {
            // Set to "NA" if version extraction fails
            #[allow(unused_unsafe)]
            unsafe {
                env::set_var("EVM_ARITHMETIZATION_PKG_VER", "NA");
            }
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

    let runtime = Runtime::from_config(&args.paladin, register()).await?;

    match args.command.clone() {
        Command::Stdio {
            previous_proof,
            save_inputs_on_error,
        } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            stdio::stdio_main(runtime, previous_proof, save_inputs_on_error).await?;
        }
        Command::Http {
            port,
            output_dir,
            save_inputs_on_error,
        } => {
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
        Command::Jerigon {
            rpc_url,
            block_interval,
            checkpoint_block_number,
            previous_proof,
            proof_output_dir,
            save_inputs_on_error,
            block_time,
            keep_intermediate_proofs,
            backoff,
            max_retries,
        }
        | Command::Native {
            rpc_url,
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
                    rpc_type: args.command.into(),
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
