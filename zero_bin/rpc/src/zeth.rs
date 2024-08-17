use alloy::{
    primitives::B256, providers::Provider, rpc::types::eth::BlockId, transports::Transport,
};
use prover::BlockProverInput;
use trace_decoder::BlockTrace;

use super::{fetch_other_block_data, CachedProvider};

pub async fn block_prover_input<ProviderT, TransportT>(
    provider: &CachedProvider<ProviderT, TransportT>,
    target_block_id: BlockId,
    checkpoint_state_trie_root: B256,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let block_number = match target_block_id {
        BlockId::Number(block_number) => block_number,
        _ => return Err(anyhow::anyhow!("block number expected")),
    };

    let block_trace = provider
        .as_provider()
        .raw_request::<_, BlockTrace>("zero_getBlockTraceByNumber".into(), vec![block_number])
        .await?;

    let other_data =
        fetch_other_block_data(provider, target_block_id, checkpoint_state_trie_root).await?;

    // Assemble
    Ok(BlockProverInput {
        block_trace,
        other_data,
    })
}
