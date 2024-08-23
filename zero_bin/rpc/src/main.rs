use std::env;
use std::sync::Arc;

use alloy::rpc::types::eth::BlockId;
use alloy::rpc::types::{BlockNumberOrTag, BlockTransactionsKind};
use clap::{Parser, ValueHint};
use futures::StreamExt;
use rpc::provider::CachedProvider;
use rpc::{retry::build_http_retry_provider, RpcType};
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;
use zero_bin_common::pre_checks::check_previous_proof_and_checkpoint;
use zero_bin_common::version;
use zero_bin_common::{block_interval::BlockInterval, prover_state::persistence::CIRCUIT_VERSION};

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
        checkpoint_block_number: Option<u64>,
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
                let checkpoint_block_number = checkpoint_block_number.unwrap_or(start_block - 1);
                check_previous_proof_and_checkpoint(checkpoint_block_number, &None, start_block)?;
                let block_interval = BlockInterval::Range(start_block..end_block + 1);

                let cached_provider = Arc::new(CachedProvider::new(build_http_retry_provider(
                    rpc_url.clone(),
                    backoff,
                    max_retries,
                )));

                // Grab interval checkpoint block state trie
                let checkpoint_state_trie_root = cached_provider
                    .get_block(
                        BlockId::Number(checkpoint_block_number.into()),
                        BlockTransactionsKind::Hashes,
                    )
                    .await?
                    .header
                    .state_root;

                let mut block_prover_inputs = Vec::new();
                let mut block_interval = block_interval.clone().into_bounded_stream()?;
                while let Some(block_num) = block_interval.next().await {
                    let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num));
                    // Get the prover input for particular block.
                    let result = rpc::block_prover_input(
                        cached_provider.clone(),
                        block_id,
                        checkpoint_state_trie_root,
                        rpc_type,
                    )
                    .await?;

                    block_prover_inputs.push(result);
                }

                serde_json::to_writer_pretty(std::io::stdout(), &block_prover_inputs)?;
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--version".to_string()) {
        version::print_version(
            CIRCUIT_VERSION.as_str(),
            env!("VERGEN_RUSTC_COMMIT_HASH"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        );
        return Ok(());
    }

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
