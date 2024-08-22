use std::io::{Read, Write};

use anyhow::Result;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use prover::{BlockProverInput, BlockProverInputFuture};
use tracing::info;

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(
    runtime: Runtime,
    previous: Option<GeneratedBlockProof>,
    save_inputs_on_error: bool,
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
        &runtime,
        previous,
        save_inputs_on_error,
        None,
    )
    .await;
    runtime.close().await?;
    let proved_blocks = proved_blocks?;

    if cfg!(feature = "test_only") {
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
