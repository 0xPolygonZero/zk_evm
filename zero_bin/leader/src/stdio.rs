use std::io::{Read, Write};

use anyhow::Result;
use proof_gen::proof_types::GeneratedBlockProof;
use prover::{BlockProverInput, BlockProverInputFuture, ProverConfig};
use tracing::info;
use zero_bin_common::proof_runtime::ProofRuntime;

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(
    proof_runtime: ProofRuntime,
    previous: Option<GeneratedBlockProof>,
    prover_config: ProverConfig,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_prover_inputs = serde_path_to_error::deserialize::<_, Vec<BlockProverInput>>(des)?
        .into_iter()
        .map(Into::into)
        .collect::<Vec<BlockProverInputFuture>>();

    let proved_blocks = prover::prove(
        block_prover_inputs,
        &proof_runtime,
        previous,
        prover_config,
        None,
    )
    .await;
    proof_runtime.block_proof_runtime.close().await?;
    proof_runtime.segment_proof_runtime.close().await?;
    let proved_blocks = proved_blocks?;

    if prover_config.test_only {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    let proofs: Vec<GeneratedBlockProof> = proved_blocks
        .into_iter()
        .filter_map(|(_, proof)| proof)
        .collect();
    std::io::stdout().write_all(&serde_json::to_vec(&proofs)?)?;

    Ok(())
}
