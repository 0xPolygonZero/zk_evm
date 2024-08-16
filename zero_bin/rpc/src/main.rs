use std::env;
use std::sync::Arc;

use alloy::primitives::B256;
use alloy::providers::Provider;
use alloy::rpc::types::eth::BlockId;
use alloy::rpc::types::{BlockNumberOrTag, BlockTransactionsKind};
use alloy::transports::Transport;
use clap::{Args, Parser, Subcommand, ValueHint};
use evm_arithmetization::GenerationInputs;
use futures::StreamExt;
use prover::BlockProverInput;
use rpc::provider::CachedProvider;
use rpc::{retry::build_http_retry_provider, RpcType};
use serde::{Deserialize, Serialize};
use tracing_subscriber::{prelude::*, EnvFilter};
use url::Url;
use zero_bin_common::pre_checks::check_previous_proof_and_checkpoint;
use zero_bin_common::version;
use zero_bin_common::{block_interval::BlockInterval, prover_state::persistence::CIRCUIT_VERSION};

#[derive(Args, Clone, Debug)]
pub(crate) struct Params {
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
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Fetch {},
    Extract {
        /// Transaction hash
        #[arg(long, short)]
        tx: String,
    },
}

#[derive(Parser)]
pub(crate) struct Cli {
    #[clap(flatten)]
    pub(crate) params: Params,

    /// Fetch and generate prover input from the RPC endpoint
    #[command(subcommand)]
    pub(crate) command: Command,
}

pub(crate) async fn retrieve_block_prover_inputs<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    block_interval: BlockInterval,
    params: &Params,
) -> Result<Vec<BlockProverInput>, anyhow::Error>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let checkpoint_block_number = params
        .checkpoint_block_number
        .unwrap_or((params.start_block - 1).into());

    // Grab interval checkpoint block state trie
    let checkpoint_state_trie_root = cached_provider
        .get_block(checkpoint_block_number, BlockTransactionsKind::Hashes)
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
            params.rpc_type,
        )
        .await?;

        block_prover_inputs.push(result);
    }
    Ok(block_prover_inputs)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum ExtractedInfo {
    Transaction {
        block_number: u64,
        txn_index: usize,
        txn_hash: B256,
        data: GenerationInputs,
    }, //TODO Add Batch variant here when feat/continuations are merged
}

impl Cli {
    /// Execute the cli command.
    pub async fn execute(self) -> anyhow::Result<()> {
        let block_interval =
            BlockInterval::Range(self.params.start_block..self.params.end_block + 1);

        let cached_provider = Arc::new(CachedProvider::new(build_http_retry_provider(
            self.params.rpc_url.clone(),
            self.params.backoff,
            self.params.max_retries,
        )));

        match self.command {
            Command::Fetch {} => {
                let block_prover_inputs =
                    retrieve_block_prover_inputs(cached_provider, block_interval, &self.params)
                        .await?;
                serde_json::to_writer_pretty(std::io::stdout(), &block_prover_inputs)?;
            }
            Command::Extract { tx } => {
                let tx_hash: B256 = tx.parse()?;
                let block_prover_inputs = retrieve_block_prover_inputs(
                    cached_provider.clone(),
                    block_interval.clone(),
                    &self.params,
                )
                .await?;
                let mut extracted_transactions: Vec<ExtractedInfo> = Vec::new();

                // Filter transactions
                for block_prover_input in block_prover_inputs {
                    let block_number: u64 = block_prover_input.get_block_number().try_into()?;
                    let block = cached_provider
                        .get_block(
                            BlockId::Number(BlockNumberOrTag::Number(block_number)),
                            BlockTransactionsKind::Hashes,
                        )
                        .await?;
                    let generation_inputs = trace_decoder::entrypoint(
                        block_prover_input.block_trace,
                        block_prover_input.other_data,
                        |_| unimplemented!(),
                    )?;

                    if let Some((index, hash)) = block
                        .transactions
                        .hashes()
                        .enumerate()
                        .find(|it| *it.1 == tx_hash)
                    {
                        extracted_transactions.push(ExtractedInfo::Transaction {
                            block_number,
                            txn_index: index,
                            txn_hash: *hash,
                            data: generation_inputs
                                .get(index)
                                .cloned()
                                .expect("Existing transaction"),
                        })
                    }
                }
                if !extracted_transactions.is_empty() {
                    serde_json::to_writer(std::io::stdout(), &extracted_transactions)?;
                } else {
                    println!(
                        "Transaction {} not found in block interval {}",
                        tx, block_interval
                    )
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
