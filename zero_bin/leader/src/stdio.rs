use std::io::{Read, Write};

use anyhow::Result;
use paladin::runtime::Runtime;
use plonky_block_proof_gen::types::PlonkyProofIntern;
use prover::ProverInput;

/// The main function for the stdio mode.
pub(crate) async fn stdio_main(
    runtime: Runtime,
    previous: Option<PlonkyProofIntern>,
) -> Result<()> {
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let input: ProverInput = serde_path_to_error::deserialize(des)?;
    let proof = input.prove(&runtime, previous).await;
    runtime.close().await?;
    let proof = proof?;

    std::io::stdout().write_all(&serde_json::to_vec(&proof.intern)?)?;

    Ok(())
}
