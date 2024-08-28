use alloy::{
    primitives::B256, providers::Provider, rpc::types::eth::BlockId, transports::Transport,
};
use anyhow::Context as _;
use prover::BlockProverInput;
use serde::Deserialize;
use serde_json::json;
use trace_decoder::{BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TxnInfo};

use super::fetch_other_block_data;
use zero_bin_common::provider::CachedProvider;

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
    checkpoint_state_trie_root: B256,
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
        .raw_request::<_, String>("eth_getWitness".into(), vec![target_block_id])
        .await?;

    let other_data =
        fetch_other_block_data(cached_provider, target_block_id, checkpoint_state_trie_root)
            .await?;

    // Assemble
    Ok(BlockProverInput {
        block_trace: BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Combined(CombinedPreImages {
                compact: hex::decode(block_witness.strip_prefix("0x").unwrap_or(&block_witness))
                    .context("invalid hex returned from call to eth_getWitness")?,
            }),
            txn_info: tx_results.into_iter().map(|it| it.result).collect(),
            code_db: Default::default(),
        },
        other_data,
    })
}
