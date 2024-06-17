use std::io;

use alloy::rpc::types::eth::BlockId;
use clap::{Parser, ValueHint};
use common::block_interval::BlockInterval;
use rpc::{retry::build_http_retry_provider, RpcType};
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;

#[derive(Parser)]
pub enum Cli {
    /// Fetch and generate prover input from the RPC endpoint
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
        /// The RPC Tracer Type
        #[arg(short = 't', long, default_value = "jerigon")]
        rpc_type: RpcType,
        /// The checkpoint block number. If not provided,
        /// block before the `start_block` is the checkpoint
        #[arg(short, long)]
        checkpoint_block_number: Option<BlockId>,
        /// Backoff in milliseconds for request retries
        #[arg(long, default_value_t = 0)]
        backoff: u64,
        /// The maximum number of retries
        #[arg(long, default_value_t = 0)]
        max_retries: u32,
    },
}

impl Cli {
    /// Execute the cli command.
    pub async fn execute(self) -> anyhow::Result<()> {
        match self {
            Self::Fetch {
                start_block,
                end_block,
                rpc_url,
                rpc_type,
                checkpoint_block_number,
                backoff,
                max_retries,
            } => {
                let checkpoint_block_number =
                    checkpoint_block_number.unwrap_or((start_block - 1).into());
                let block_interval = BlockInterval::Range(start_block..end_block + 1);

                // Retrieve prover input from the Erigon node
                let prover_input = rpc::prover_input(
                    &build_http_retry_provider(rpc_url, backoff, max_retries),
                    block_interval,
                    checkpoint_block_number,
                    rpc_type,
                )
                .await?;

                serde_json::to_writer_pretty(io::stdout(), &prover_input.blocks)?;
            }
        }
        Ok(())
    }
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

    Cli::parse().execute().await
}
