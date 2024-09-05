use std::sync::Arc;

use alloy::rpc::types::{BlockId, BlockNumberOrTag, BlockTransactionsKind};
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Result};
use proof_gen::proof_types::GeneratedBlockProof;
use prover::{BlockProverInput, ProverConfig};
use rpc::{retry::build_http_retry_provider, RpcType};
use tokio::sync::mpsc;
use tracing::info;
use zero_bin_common::block_interval::{BlockInterval, BlockIntervalStream};
use zero_bin_common::pre_checks::check_previous_proof_and_checkpoint;
use zero_bin_common::proof_runtime::ProofRuntime;

#[derive(Debug)]
pub struct RpcParams {
    pub rpc_url: Url,
    pub rpc_type: RpcType,
    pub backoff: u64,
    pub max_retries: u32,
    pub block_time: u64,
}

#[derive(Debug)]
pub struct LeaderConfig {
    pub checkpoint_block_number: u64,
    pub previous_proof: Option<GeneratedBlockProof>,
    pub prover_config: ProverConfig,
}

/// The main function for the client.
pub(crate) async fn client_main(
    proof_runtime: Arc<ProofRuntime>,
    rpc_params: RpcParams,
    block_interval: BlockInterval,
    mut leader_config: LeaderConfig,
) -> Result<()> {
    use futures::StreamExt;

    let cached_provider = Arc::new(zero_bin_common::provider::CachedProvider::new(
        build_http_retry_provider(
            rpc_params.rpc_url.clone(),
            rpc_params.backoff,
            rpc_params.max_retries,
        )?,
    ));
    check_previous_proof_and_checkpoint(
        leader_config.checkpoint_block_number,
        &leader_config.previous_proof,
        block_interval.get_start_block()?,
    )?;
    // Grab interval checkpoint block state trie.
    let checkpoint_state_trie_root = cached_provider
        .get_block(
            leader_config.checkpoint_block_number.into(),
            BlockTransactionsKind::Hashes,
        )
        .await?
        .header
        .state_root;

    // Create a channel for block prover input and use it to send prover input to
    // the proving task. The second element of the tuple is a flag indicating
    // whether the block is the last one in the interval.
    let (block_tx, block_rx) =
        mpsc::channel::<(BlockProverInput, bool)>(zero_bin_common::BLOCK_CHANNEL_SIZE);
    let test_only = leader_config.prover_config.test_only;

    // Run proving task
    let proof_runtime_ = proof_runtime.clone();
    let proving_task = tokio::spawn(prover::prove(
        block_rx,
        proof_runtime_,
        leader_config.previous_proof.take(),
        Arc::new(leader_config.prover_config),
    ));

    // Create block interval stream. Could be bounded or unbounded.
    let mut block_interval_stream: BlockIntervalStream = match block_interval {
        block_interval @ BlockInterval::FollowFrom { .. } => {
            block_interval
                .into_unbounded_stream(cached_provider.clone(), rpc_params.block_time)
                .await?
        }
        _ => block_interval.into_bounded_stream()?,
    };

    // Iterate over the block interval, retrieve prover input
    // and send it to the proving task
    while let Some(block_interval_elem) = block_interval_stream.next().await {
        let (block_num, is_last_block) = block_interval_elem?;
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num));
        // Get prover input for particular block.
        let block_prover_input = rpc::block_prover_input(
            cached_provider.clone(),
            block_id,
            checkpoint_state_trie_root,
            rpc_params.rpc_type,
        )
        .await?;
        block_tx
            .send((block_prover_input, is_last_block))
            .await
            .map_err(|e| anyhow!("failed to send block prover input through the channel: {e}"))?;
    }

    match proving_task.await {
        Ok(Ok(_)) => {
            info!("Proving task successfully finished");
        }
        Ok(Err(e)) => {
            anyhow::bail!("Proving task finished with error: {e:?}");
        }
        Err(e) => {
            anyhow::bail!("Unable to join proving task, error: {e:?}");
        }
    }

    proof_runtime.block_proof_runtime.close().await?;
    proof_runtime.segment_proof_runtime.close().await?;

    if test_only {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    Ok(())
}
