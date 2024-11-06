use alloy::{providers::Provider, rpc::types::eth::BlockId, transports::Transport};
use anyhow::Context as _;
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
        .await?;

    // Grab block witness info (packed as combined trie pre-images)

    let block_witness = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, String>(WITNESS_ENDPOINT.into(), vec![target_block_id])
        .await?;

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
            txn_info: tx_results.into_iter().map(|it| it.result).collect(),
            code_db: Default::default(),
        },
        other_data,
    })
}
