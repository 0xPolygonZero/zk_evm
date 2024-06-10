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
        /// The RPC URL.
        #[arg(short = 'u', long, value_hint = ValueHint::Url)]
        rpc_url: Url,
        /// The block number.
        #[arg(short, long)]
        block_number: BlockId,
        /// The checkpoint block number.
        #[arg(short, long, default_value = "0")]
        checkpoint_block_number: BlockId,
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
        rpc_url,
        block_number,
        checkpoint_block_number,
    } = Args::parse();
    let prover_input = rpc::prover_input(
        RootProvider::new_http(rpc_url),
        BlockInterval::SingleBlockId(block_number),
        checkpoint_block_number,
    )
    .await?;

    serde_json::to_writer_pretty(io::stdout(), &prover_input)?;

    Ok(())
}
