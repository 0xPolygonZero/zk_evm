use std::io;

use alloy::{providers::RootProvider, rpc::types::eth::BlockId};
use clap::{Parser, ValueHint};
use common::block_interval::BlockInterval;
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;

#[derive(Parser)]
pub enum Args {
    /// Fetch and generate prover input from the RPC endpoint.
    Fetch {
        // Starting block of interval to fetch
        #[arg(short, long)]
        start_block: u64,
        // End block of interval to fetch
        #[arg(short, long)]
        end_block: u64,
        /// The RPC URL.
        #[arg(short = 'u', long, value_hint = ValueHint::Url)]
        rpc_url: Url,
        /// The checkpoint block number. If not provided,
        /// block before the `start_block` is the checkpoint
        #[arg(short, long)]
        checkpoint_block_number: Option<BlockId>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .compact()
                .with_filter(EnvFilter::from_default_env()),
        )
        .init();

    let Args::Fetch {
        start_block,
        end_block,
        rpc_url,
        checkpoint_block_number,
    } = Args::parse();

    let checkpoint_block_number = checkpoint_block_number.unwrap_or((start_block - 1).into());
    let block_interval = BlockInterval::Range(start_block..end_block + 1);

    // Retrieve prover input from the Erigon node
    let prover_input = rpc::prover_input(
        RootProvider::new_http(rpc_url),
        block_interval,
        checkpoint_block_number,
    )
    .await?;

    serde_json::to_writer_pretty(io::stdout(), &prover_input.blocks)?;

    Ok(())
}
