use std::io::Write;

use anyhow::Result;
use clap::Parser;
use cli::Commands;
use rpc::fetch_prover_input;

mod cli;
mod init;
mod rpc;

#[tokio::main]
async fn main() -> Result<()> {
    init::tracing();
    let args = cli::Cli::parse();

    match args.command {
        Commands::Fetch {
            rpc_url,
            block_number,
        } => {
            let prover_input = fetch_prover_input(&rpc_url, block_number).await?;
            std::io::stdout().write_all(&serde_json::to_vec(&prover_input)?)?;
        }
    }
    Ok(())
}
