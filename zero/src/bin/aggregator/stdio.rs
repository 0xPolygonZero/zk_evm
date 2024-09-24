use std::io::Read;
use std::sync::Arc;

use anyhow::{ensure, Result};
use paladin::runtime::Runtime;
use tracing::{error, info};
use zero::{
    fs::write_proof_to_dir,
    proof_types::{AggregatableBlockProof, GeneratedBlockProof},
    prover::ProverConfig,
};

/// The main function for the stdio mode.
pub(crate) async fn stdio_wrap(
    runtime: Arc<Runtime>,
    prover_config: Arc<ProverConfig>,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_proof = serde_path_to_error::deserialize::<_, Vec<GeneratedBlockProof>>(des)?
        .into_iter()
        .collect::<Vec<_>>();

    ensure!(
        block_proof.len() == 1,
        "Expected one and only one block proof to be wrapped, got {:?}",
        block_proof.len()
    );
    let block_proof = block_proof[0].clone();
    let block_number = block_proof.b_height;

    let proving_task = tokio::spawn(crate::wrap(
        block_proof,
        runtime.clone(),
        prover_config.clone(),
    ));

    let proof = match proving_task.await {
        Ok(Ok(proof)) => {
            info!("Proving task successfully finished");
            AggregatableBlockProof::Block(proof)
        }
        Ok(Err(e)) => {
            anyhow::bail!("Proving task finished with error: {e:?}");
        }
        Err(e) => {
            anyhow::bail!("Unable to join proving task, error: {e:?}");
        }
    };

    runtime.close().await?;

    write_proof_to_dir(&prover_config.proof_output_dir, proof)
        .await
        .inspect_err(|e| {
            error!("failed to output wrapped proof for block {block_number} to directory {e:?}")
        })?;

    Ok(())
}

/// The main function for the stdio mode.
pub(crate) async fn stdio_aggregate(
    runtime: Arc<Runtime>,
    prover_config: Arc<ProverConfig>,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_proofs = serde_path_to_error::deserialize::<_, Vec<AggregatableBlockProof>>(des)?
        .into_iter()
        .collect::<Vec<_>>();

    let proving_task = tokio::spawn(crate::aggregate(
        block_proofs,
        runtime.clone(),
        prover_config.clone(),
    ));

    let proof = match proving_task.await {
        Ok(Ok(proof)) => {
            info!("Proving task successfully finished");
            proof
        }
        Ok(Err(e)) => {
            anyhow::bail!("Proving task finished with error: {e:?}");
        }
        Err(e) => {
            anyhow::bail!("Unable to join proving task, error: {e:?}");
        }
    };

    runtime.close().await?;

    write_proof_to_dir(&prover_config.proof_output_dir, proof)
        .await
        .inspect_err(|e| error!("failed to output aggregated block proof to directory {e:?}"))?;

    Ok(())
}
