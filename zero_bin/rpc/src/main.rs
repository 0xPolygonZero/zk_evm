use std::env;
use std::sync::Arc;

use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockId;
use alloy::rpc::types::{BlockNumberOrTag, BlockTransactionsKind};
use alloy::transports::Transport;
use anyhow::anyhow;
use clap::{Args, Parser, Subcommand, ValueHint};
use futures::StreamExt;
use prover::BlockProverInput;
use zero_bin_common::provider::CachedProvider;
use rpc::{retry::build_http_retry_provider, RpcParams, RpcType};
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;
use zero_bin_common::pre_checks::check_previous_proof_and_checkpoint;
use zero_bin_common::version;
use zero_bin_common::{block_interval::BlockInterval, prover_state::persistence::CIRCUIT_VERSION};

#[derive(Args, Clone, Debug)]
pub(crate) struct RpcConfig {
    /// The RPC URL.
    #[arg(short = 'u', long, value_hint = ValueHint::Url)]
    rpc_url: Url,
    /// The RPC Tracer Type.
    #[arg(short = 't', long, default_value = "jerigon")]
    rpc_type: RpcType,
    /// Backoff in milliseconds for retry requests.
    #[arg(long, default_value_t = 0)]
    backoff: u64,
    /// The maximum number of retries.
    #[arg(long, default_value_t = 0)]
    max_retries: u32,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Fetch {
        /// Starting block of interval to fetch.
        #[arg(short, long)]
        start_block: u64,
        /// End block of interval to fetch.
        #[arg(short, long)]
        end_block: u64,
        /// The checkpoint block number. If not provided,
        /// the block before the `start_block` is the checkpoint.
        #[arg(short, long)]
        checkpoint_block_number: Option<u64>,
    },
    Extract {
        /// Transaction hash.
        #[arg(long, short)]
        tx: String,
        /// Number of transactions in a batch to process at once.
        #[arg(short, long, default_value_t = 1)]
        batch_size: usize,
    },
}

#[derive(Parser)]
pub(crate) struct Cli {
    #[clap(flatten)]
    pub(crate) config: RpcConfig,

    /// Fetch and generate prover input from the RPC endpoint.
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(crate) async fn retrieve_block_prover_inputs<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    params: RpcParams,
) -> Result<Vec<BlockProverInput>, anyhow::Error>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let checkpoint_block_number = params
        .checkpoint_block_number
        .unwrap_or(params.start_block - 1);
    check_previous_proof_and_checkpoint(checkpoint_block_number, &None, params.start_block)?;

    // Grab interval checkpoint block state trie
    let checkpoint_state_trie_root = cached_provider
        .get_block(
            BlockId::Number(checkpoint_block_number.into()),
            BlockTransactionsKind::Hashes,
        )
        .await?
        .header
        .state_root;

    let block_interval = BlockInterval::Range(params.start_block..params.end_block + 1);
    let mut block_prover_inputs = Vec::new();
    let mut block_interval = block_interval.clone().into_bounded_stream()?;
    while let Some(block_num) = block_interval.next().await {
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num));
        // Get the prover input for particular block.
        let result = rpc::block_prover_input(
            cached_provider.clone(),
            block_id,
            checkpoint_state_trie_root,
            params.rpc_type,
        )
        .await?;

        block_prover_inputs.push(result);
    }
    Ok(block_prover_inputs)
}

impl Cli {
    /// Execute the cli command.
    pub async fn execute(self) -> anyhow::Result<()> {
        let cached_provider = Arc::new(CachedProvider::new(build_http_retry_provider(
            self.config.rpc_url.clone(),
            self.config.backoff,
            self.config.max_retries,
        )?));

        match self.command {
            Command::Fetch {
                start_block,
                end_block,
                checkpoint_block_number,
            } => {
                let params = RpcParams {
                    start_block,
                    end_block,
                    checkpoint_block_number,
                    rpc_type: self.config.rpc_type,
                };

                let block_prover_inputs =
                    retrieve_block_prover_inputs(cached_provider, params).await?;
                serde_json::to_writer_pretty(std::io::stdout(), &block_prover_inputs)?;
            }
            Command::Extract { tx, batch_size } => {
                let tx_hash: B256 = tx.parse()?;
                // Get transaction info.
                match cached_provider
                    .clone()
                    .get_provider()
                    .await?
                    .get_transaction_by_hash(tx_hash)
                    .await?
                {
                    Some(tx_info) => {
                        let block_number = tx_info.block_number.ok_or(anyhow!(
                            "transaction {} does not have block number",
                            tx_hash
                        ))?;
                        let params = RpcParams {
                            start_block: block_number,
                            end_block: block_number,
                            checkpoint_block_number: None,
                            rpc_type: self.config.rpc_type,
                        };

                        let block_prover_inputs =
                            retrieve_block_prover_inputs(cached_provider, params).await?;

                        let block_prover_input =
                            block_prover_inputs.into_iter().next().ok_or(anyhow!(
                                "error, block prover input for block {} not retrieved",
                                block_number
                            ))?;

                        let generation_inputs = trace_decoder::entrypoint(
                            block_prover_input.block_trace,
                            block_prover_input.other_data,
                            batch_size,
                        )?;

                        if let Some(index) = tx_info.transaction_index {
                            let generation_input_index = if batch_size == 1 {
                                // If batch size is 1, it means one transaction per
                                // GenerationInputs. Take element
                                // with txn index from the GenerationInput array.
                                index as usize
                            } else {
                                // Batch size bigger than one, meaning multiple transactions in one
                                // GenerationInput. Find GenerationInput
                                // where the transaction is placed.
                                index as usize / batch_size
                            };
                            let extracted_generation_input =
                                generation_inputs.get(generation_input_index).cloned();
                            serde_json::to_writer(std::io::stdout(), &extracted_generation_input)?;
                        } else {
                            anyhow::bail!("invalid transaction index for transaction {}", tx_hash);
                        }
                    }
                    None => {
                        anyhow::bail!("unable to find transaction {}", tx_hash);
                    }
                }
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
