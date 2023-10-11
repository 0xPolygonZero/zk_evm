#![feature(iter_array_chunks)]

use anyhow::Result;
use clap::Parser;
use cli::Mode;
use plonky_block_proof_gen::prover_state::ProverStateBuilder;

mod cli;
mod http;
mod init;
mod prover_input;
mod stdio;

#[tokio::main]
async fn main() -> Result<()> {
    init::init();

    let cli = cli::Cli::parse();
    let p_state = ProverStateBuilder::default().build();

    match cli.mode {
        Mode::StdIo => {
            stdio::stdio_main(p_state)?;
        }
        Mode::Http => {
            http::http_main(p_state, cli.port).await?;
        }
    }

    Ok(())
}
