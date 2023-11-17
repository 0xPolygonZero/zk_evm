use std::io::Write;

use anyhow::Result;
use paladin::runtime::Runtime;
use plonky_block_proof_gen::types::PlonkyProofIntern;

/// The main function for the jerigon mode.
pub(crate) async fn jerigon_main(
    runtime: Runtime,
    rpc_url: &str,
    block_number: u64,
    previous: Option<PlonkyProofIntern>,
) -> Result<()> {
    let prover_input = rpc::fetch_prover_input(rpc_url, block_number).await?;

    let proof = prover_input.prove(&runtime, previous).await;
    runtime.close().await?;
    let proof = proof?;
    std::io::stdout().write_all(&serde_json::to_vec(&proof.intern)?)?;

    Ok(())
}
