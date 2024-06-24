use alloy::{
    primitives::B256, providers::Provider, rpc::types::eth::BlockId, transports::Transport,
};
use prover::BlockProverInput;
use serde::Deserialize;
use serde_json::json;
use trace_decoder::trace_protocol::{
    BlockTrace, BlockTraceTriePreImages, CombinedPreImages, TrieCompact, TxnInfo,
};

use super::fetch_other_block_data;

/// Transaction traces retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroTxResult {
    #[serde(rename(deserialize = "txHash"))]
    pub tx_hash: alloy::primitives::TxHash,
    pub result: TxnInfo,
}

/// Block witness retrieved from Erigon zeroTracer.
#[derive(Debug, Deserialize)]
pub struct ZeroBlockWitness(TrieCompact);

pub async fn block_prover_input<ProviderT, TransportT>(
    provider: ProviderT,
    target_block_id: BlockId,
    checkpoint_state_trie_root: B256,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    // Grab trace information
    let tx_results = provider
        .raw_request::<_, Vec<ZeroTxResult>>(
            "debug_traceBlockByNumber".into(),
            (target_block_id, json!({"tracer": "zeroTracer"})),
        )
        .await?;

    // Grab block witness info (packed as combined trie pre-images)
    let block_witness = provider
        .raw_request::<_, ZeroBlockWitness>("eth_getWitness".into(), vec![target_block_id])
        .await?;

    let other_data =
        fetch_other_block_data(provider, target_block_id, checkpoint_state_trie_root).await?;

    // Assemble
    Ok(BlockProverInput {
        block_trace: BlockTrace {
            trie_pre_images: BlockTraceTriePreImages::Combined(CombinedPreImages {
                compact: block_witness.0,
            }),
            txn_info: tx_results.into_iter().map(|it| it.result).collect(),
            code_db: Default::default(),
        },
        other_data,
    })
}
