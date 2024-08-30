use std::io::Read;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use prover::{BlockProverInput, ProverConfig};
use tokio::sync::mpsc;
use tracing::info;

const BLOCK_CHANNEL_SIZE: usize = 16;

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(
    runtime: Runtime,
    previous: Option<GeneratedBlockProof>,
    prover_config: ProverConfig,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let runtime = Arc::new(runtime);

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_prover_inputs = serde_path_to_error::deserialize::<_, Vec<BlockProverInput>>(des)?
        .into_iter()
        .collect::<Vec<_>>();

    let (block_tx, block_rx) = mpsc::channel::<BlockProverInput>(BLOCK_CHANNEL_SIZE);

    let runtime_ = runtime.clone();
    let proving_task = tokio::spawn(prover::prove(
        block_rx,
        runtime_,
        previous,
        prover_config,
        None,
    ));

    for block_prover_input in block_prover_inputs {
        block_tx
            .send(block_prover_input)
            .await
            .map_err(|e| anyhow!("Failed to send block prover input through the channel: {e}"))?;
    }

    let _ = proving_task.await?;
    runtime.close().await?;
    // let proved_blocks = proved_blocks?;

    if prover_config.test_only {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    // let proofs: Vec<GeneratedBlockProof> = proved_blocks
    //     .into_iter()
    //     .filter_map(|(_, proof)| proof)
    //     .collect();
    // std::io::stdout().write_all(&serde_json::to_vec(&proofs)?)?;

    Ok(())
}
