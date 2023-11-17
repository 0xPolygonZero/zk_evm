use std::{fs::File, path::PathBuf};

use anyhow::Result;
use clap::Parser;
use cli::Mode;
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
        runtime: args.runtime,
        num_workers: args.num_workers,
        ..Default::default()
    })
    .await?;

    match args.mode {
        Mode::StdIo => {
            let previous_proof = get_previous_proof(args.previous_proof)?;
            stdio::stdio_main(runtime, previous_proof).await?;
        }
        Mode::Http => {
            let output_dir = args
                .output_dir
                .expect("output-dir is required in http mode");

            // check if output_dir exists, is a directory, and is writable
            let output_dir_metadata = std::fs::metadata(&output_dir)?;
            if !output_dir.is_dir() || output_dir_metadata.permissions().readonly() {
                panic!("output-dir is not a writable directory");
            }

            http::http_main(runtime, args.port, output_dir).await?;
        }
        Mode::Jerigon => {
            let rpc_url = args.rpc_url.expect("rpc-url is required in jerigon mode");
            let block_number = args
                .block_number
                .expect("block-number is required in jerigon mode");
            let previous_proof = get_previous_proof(args.previous_proof)?;

            jerigon::jerigon_main(runtime, &rpc_url, block_number, previous_proof).await?;
        }
    }

    Ok(())
}
