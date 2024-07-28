use std::{env, io};

use alloy::rpc::types::eth::BlockId;
use clap::{Parser, ValueHint};
use rpc::provider::CachedProvider;
use rpc::{retry::build_http_retry_provider, RpcType};
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;
use zero_bin_common::block_interval::BlockInterval;

const EVM_ARITH_VER_KEY: &str = "EVM_ARITHMETIZATION_PKG_VER";
const VERGEN_BUILD_TIMESTAMP: &str = "VERGEN_BUILD_TIMESTAMP";
const VERGEN_RUSTC_COMMIT_HASH: &str = "VERGEN_RUSTC_COMMIT_HASH";

#[derive(Parser)]
pub enum Cli {
    /// Print the version of the rpc package
    Version {},
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
            Self::Version {} => {
                println!(
                    "Evm Arithmetization package version: {}",
                    env::var(EVM_ARITH_VER_KEY)?
                );
                println!("Build Commit Hash: {}", env::var(VERGEN_RUSTC_COMMIT_HASH)?);
                println!("Build Timestamp: {}", env::var(VERGEN_BUILD_TIMESTAMP)?);
            }
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

                let cached_provider = CachedProvider::new(build_http_retry_provider(
                    rpc_url.clone(),
                    backoff,
                    max_retries,
                ));

                // Retrieve prover input from the Erigon node
                let prover_input = rpc::prover_input(
                    &cached_provider,
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
    if env::var_os(EVM_ARITH_VER_KEY).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                EVM_ARITH_VER_KEY,
                // see build.rs
                env!("EVM_ARITHMETIZATION_PACKAGE_VERSION"),
            );
        }
    }
    if env::var_os(VERGEN_BUILD_TIMESTAMP).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_BUILD_TIMESTAMP,
                // see build.rs
                env!("VERGEN_BUILD_TIMESTAMP"),
            );
        }
    }
    if env::var_os(VERGEN_RUSTC_COMMIT_HASH).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_RUSTC_COMMIT_HASH,
                // see build.rs
                env!("VERGEN_RUSTC_COMMIT_HASH"),
            );
        }
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
