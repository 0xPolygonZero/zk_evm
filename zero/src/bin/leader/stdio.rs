use std::io::Read;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use paladin::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::info;
use zero::proof_types::GeneratedBlockProof;
use zero::prover::{self, BlockProverInput, ProverConfig};

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(
    runtime: Arc<Runtime>,
    previous: Option<GeneratedBlockProof>,
    prover_config: Arc<ProverConfig>,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_prover_inputs = serde_path_to_error::deserialize::<_, Vec<BlockProverInput>>(des)?
        .into_iter()
        .collect::<Vec<_>>();

    let (block_tx, block_rx) = mpsc::channel::<(BlockProverInput, bool)>(zero::BLOCK_CHANNEL_SIZE);

    let runtime_ = runtime.clone();
    let prover_config_ = prover_config.clone();
    let proving_task = tokio::spawn(prover::prove(block_rx, runtime_, previous, prover_config_));

    let interval_len = block_prover_inputs.len();
    for (index, block_prover_input) in block_prover_inputs.into_iter().enumerate() {
        block_tx
            .send((block_prover_input, interval_len == index + 1))
            .await
            .map_err(|e| anyhow!("Failed to send block prover input through the channel: {e}"))?;
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

    runtime.close().await?;

    if prover_config.test_only {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    Ok(())
}
