use std::ops::Deref;

use alloy::rpc::types::{Block, BlockTransactionsKind};
use alloy::{providers::Provider, rpc::types::eth::BlockId, transports::Transport};
use anyhow::Context as _;
use evm_arithmetization::structlog::{get_structlog_for_debug, TxZeroStructLogs};
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TxnInfo};

use super::fetch_other_block_data;
use crate::prover::BlockProverInput;
use crate::provider::CachedProvider;

const WITNESS_ENDPOINT: &str = if cfg!(feature = "cdk_erigon") {
    "zkevm_getWitness"
} else {
    "eth_getWitness"
};

/// Transaction traces retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroTxResult {
    #[serde(rename(deserialize = "txHash"))]
    pub tx_hash: alloy::primitives::TxHash,
    pub result: TxnInfo,
}

pub async fn block_prover_input<ProviderT, TransportT>(
    cached_provider: std::sync::Arc<CachedProvider<ProviderT, TransportT>>,
    target_block_id: BlockId,
    checkpoint_block_number: u64,
    get_struct_logs: bool,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab trace information
    let tx_results = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, Vec<ZeroTxResult>>(
            "debug_traceBlockByNumber".into(),
            (target_block_id, json!({"tracer": "zeroTracer"})),
        )
        .await?
        .into_iter()
        .map(|ztr| ztr.result)
        .collect::<Vec<_>>();

    // Grab block witness info (packed as combined trie pre-images)

    let block_witness = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, String>(WITNESS_ENDPOINT.into(), vec![target_block_id])
        .await?;

    let block = cached_provider
        .get_block(target_block_id, BlockTransactionsKind::Full)
        .await?;

    let struct_logs = match block {
        Some(b) => {
            if get_struct_logs {
                Some(process_txns(&b, cached_provider.get_provider().await?.deref()).await?)
            } else {
                None
            }
        }
        None => None,
    };
    let other_data =
        fetch_other_block_data(cached_provider, target_block_id, checkpoint_block_number).await?;
    // Assemble
    Ok(BlockProverInput {
        block_trace: BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Combined(CombinedPreImages {
                compact: hex::decode(block_witness.strip_prefix("0x").unwrap_or(&block_witness))
                    .context(format!(
                        "invalid hex returned from call to {WITNESS_ENDPOINT}"
                    ))?,
            }),
            txn_info: tx_results,
            code_db: Default::default(),
        },
        other_data,
        struct_logs,
    })
}

async fn process_txns<ProviderT, TransportT>(
    block: &Block,
    provider: &ProviderT,
) -> anyhow::Result<Vec<TxZeroStructLogs>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let all_txns = block
        .transactions
        .as_transactions()
        .context("No transactions in block")?;
    let mut struct_logs = Vec::with_capacity(all_txns.len());
    for tx in all_txns {
        struct_logs.push(get_structlog_for_debug(provider, &tx.hash).await?);
    }

    Ok(struct_logs)
}
