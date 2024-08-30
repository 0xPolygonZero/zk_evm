use std::path::PathBuf;
use std::sync::Arc;

use alloy::rpc::types::{BlockId, BlockNumberOrTag, BlockTransactionsKind};
use alloy::transports::http::reqwest::Url;
use anyhow::{anyhow, Result};
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use prover::{BlockProverInput, ProverConfig};
use rpc::{retry::build_http_retry_provider, RpcType};
use tokio::sync::mpsc;
use tracing::{error, info};
use zero_bin_common::block_interval::BlockInterval;
use zero_bin_common::pre_checks::check_previous_proof_and_checkpoint;

const BLOCK_CHANNEL_SIZE: usize = 16;

#[derive(Debug)]
pub struct RpcParams {
    pub rpc_url: Url,
    pub rpc_type: RpcType,
    pub backoff: u64,
    pub max_retries: u32,
}

#[derive(Debug)]
pub struct ProofParams {
    pub checkpoint_block_number: u64,
    pub previous_proof: Option<GeneratedBlockProof>,
    pub proof_output_dir: Option<PathBuf>,
    pub prover_config: ProverConfig,
    #[allow(dead_code)]
    pub keep_intermediate_proofs: bool,
}

/// The main function for the client.
pub(crate) async fn client_main(
    runtime: Arc<Runtime>,
    rpc_params: RpcParams,
    block_interval: BlockInterval,
    mut params: ProofParams,
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
        params.checkpoint_block_number,
        &params.previous_proof,
        block_interval.get_start_block()?,
    )?;
    // Grab interval checkpoint block state trie.
    let checkpoint_state_trie_root = cached_provider
        .get_block(
            params.checkpoint_block_number.into(),
            BlockTransactionsKind::Hashes,
        )
        .await?
        .header
        .state_root;

    let (block_tx, block_rx) = mpsc::channel::<BlockProverInput>(BLOCK_CHANNEL_SIZE);

    let runtime_ = runtime.clone();
    let prove_task = tokio::spawn(async move {
        // If `keep_intermediate_proofs` is not set we only keep the last block
        // proof from the interval. It contains all the necessary information to
        // verify the whole sequence.
        prover::prove(
            block_rx,
            runtime_,
            params.previous_proof.take(),
            params.prover_config,
            params.proof_output_dir.clone(),
        )
        .await
    });

    let mut block_interval_stream: zero_bin_common::block_interval::BlockIntervalStream =
        match block_interval {
            block_interval @ BlockInterval::FollowFrom { .. } => {
                _ = block_interval
                    .into_unbounded_stream(cached_provider.clone())
                    .await?;
                unimplemented!(
                    "refactor of the proving login is needed to support FollowFrom scenario"
                );
            }
            _ => block_interval.into_bounded_stream()?,
        };

    while let Some(block_num) = block_interval_stream.next().await {
        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_num?));
        // Get future of prover input for particular block.
        let block_prover_input = rpc::block_prover_input(
            cached_provider.clone(),
            block_id,
            checkpoint_state_trie_root,
            rpc_params.rpc_type,
        )
        .await?;
        block_tx
            .send(block_prover_input)
            .await
            .map_err(|e| anyhow!("Failed to send block prover input through the channel: {e}"))?;
    }

    if let Err(e) = tokio::try_join!(prove_task) {
        error!("Execution finished with error {e:?}");
    } else {
        info!("Proving task sucessfully finished");
    }
    runtime.close().await?;

    if params.prover_config.test_only {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    // if !params.prover_config.test_only {
    //     if params.keep_intermediate_proofs {
    //         if params.proof_output_dir.is_some() {
    //             // All proof files (including intermediary) are written to disk
    // and kept             warn!("Skipping cleanup, intermediate proof files
    // are kept");         } else {
    //             // Output all proofs to stdout
    //             std::io::stdout().write_all(&serde_json::to_vec(
    //                 &proved_blocks
    //                     .into_iter()
    //                     .filter_map(|(_, block)| block)
    //                     .collect::<Vec<_>>(),
    //             )?)?;
    //         }
    //     } else if let Some(proof_output_dir) = params.proof_output_dir.as_ref() {
    //         // Remove intermediary proof files
    //         proved_blocks
    //             .into_iter()
    //             .rev()
    //             .skip(1)
    //             .map(|(block_number, _)| {
    //                 generate_block_proof_file_name(&proof_output_dir.to_str(),
    // block_number)             })
    //             .for_each(|path| {
    //                 if let Err(e) = std::fs::remove_file(path) {
    //                     error!("Failed to remove intermediate proof file: {e}");
    //                 }
    //             });
    //     } else {
    //         // Output only last proof to stdout
    //         if let Some(last_block) = proved_blocks
    //             .into_iter()
    //             .filter_map(|(_, block)| block)
    //             .last()
    //         {
    //             std::io::stdout().write_all(&serde_json::to_vec(&last_block)?)?;
    //         }
    //     }
    // }

    Ok(())
}
