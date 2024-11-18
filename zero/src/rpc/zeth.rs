use alloy::{providers::Provider, rpc::types::eth::BlockId, transports::Transport};
use serde::Deserialize;
use trace_decoder::{BlockTrace, TxnInfo};

use super::fetch_other_block_data;
use crate::prover::BlockProverInput;
use crate::provider::CachedProvider;

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
    let block_number = match target_block_id {
        BlockId::Number(block_number) => block_number,
        _ => return Err(anyhow::anyhow!("block number expected")),
    };

    let block_trace = cached_provider
        .get_provider()
        .await?
        .raw_request::<_, BlockTrace>("zero_getBlockTraceByNumber".into(), vec![block_number])
        .await?;

    let other_data =
        fetch_other_block_data(cached_provider, target_block_id, checkpoint_block_number).await?;
    println!("block_prover_input: {:?}", block_trace);
    // Assemble
    Ok(BlockProverInput {
        block_trace,
        other_data,
    })
}
