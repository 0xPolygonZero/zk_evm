use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

use alloy::{
    providers::Provider,
    rpc::types::eth::{BlockId, BlockTransactionsKind},
    transports::Transport,
};
use futures::try_join;
use prover::BlockProverInput;
use trace_decoder::BlockTrace;
use zero_bin_common::provider::CachedProvider;

mod state;
mod txn;

type CodeDb = BTreeSet<Vec<u8>>;

/// Fetches the prover input for the given BlockId.
pub async fn block_prover_input<ProviderT, TransportT>(
    provider: Arc<CachedProvider<ProviderT, TransportT>>,
    block_number: BlockId,
    checkpoint_block_number: u64,
) -> anyhow::Result<BlockProverInput>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let (block_trace, other_data) = try_join!(
        process_block_trace(provider.clone(), block_number),
        crate::fetch_other_block_data(provider.clone(), block_number, checkpoint_block_number)
    )?;

    Ok(BlockProverInput {
        block_trace,
        other_data,
    })
}

/// Processes the block with the given block number and returns the block trace.
async fn process_block_trace<ProviderT, TransportT>(
    cached_provider: Arc<CachedProvider<ProviderT, TransportT>>,
    block_number: BlockId,
) -> anyhow::Result<BlockTrace>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let block = cached_provider
        .get_block(block_number, BlockTransactionsKind::Full)
        .await?;

    let (code_db, txn_info) =
        txn::process_transactions(&block, cached_provider.get_provider().await?.deref()).await?;
    let trie_pre_images = state::process_state_witness(cached_provider, block, &txn_info).await?;

    Ok(BlockTrace {
        txn_info,
        code_db,
        trie_pre_images,
    })
}
