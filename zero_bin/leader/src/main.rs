use std::{fs::File, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use cli::Command;
use dotenvy::dotenv;
use ops::Ops;
use paladin::runtime::Runtime;
use plonky_block_proof_gen::types::PlonkyProofIntern;

mod cli;
mod http;
mod init;
mod jerigon;
mod stdio;

fn get_previous_proof(path: Option<PathBuf>) -> Result<Option<PlonkyProofIntern>> {
    if path.is_none() {
        return Ok(None);
    }

    let path = path.unwrap();
    let file = File::open(path)?;
    let des = &mut serde_json::Deserializer::from_reader(&file);
    let proof: PlonkyProofIntern = serde_path_to_error::deserialize(des)?;
    Ok(Some(proof))
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();

    let args = cli::Cli::parse();
    let runtime = Runtime::from_config::<Ops>(&paladin::config::Config {
        runtime: args.runtime.runtime,
        num_workers: args.runtime.num_workers,
        amqp_uri: args.runtime.amqp_uri,
        ..Default::default()
    })
    .await?;

    match args.command {
        Command::Stdio { previous_proof } => {
            let previous_proof = get_previous_proof(previous_proof)?;
            stdio::stdio_main(runtime, previous_proof).await?;
        }
        Command::Http { port, output_dir } => {
            // check if output_dir exists, is a directory, and is writable
            let output_dir_metadata = std::fs::metadata(&output_dir)?;
            if !output_dir.is_dir() || output_dir_metadata.permissions().readonly() {
                panic!("output-dir is not a writable directory");
            }

            http::http_main(runtime, port, output_dir).await?;
        }
        Command::Jerigon {
            rpc_url,
            block_number,
            previous_proof,
        } => {
            let previous_proof = get_previous_proof(previous_proof)?;

            jerigon::jerigon_main(runtime, &rpc_url, block_number, previous_proof).await?;
        }
    }

    Ok(())
}
