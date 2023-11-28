use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::PathBuf,
};

use anyhow::{Context, Result};
use paladin::runtime::Runtime;
use plonky_block_proof_gen::types::PlonkyProofIntern;

/// The main function for the jerigon mode.
pub(crate) async fn jerigon_main(
    runtime: Runtime,
    rpc_url: &str,
    block_number: u64,
    previous: Option<PlonkyProofIntern>,
    proof_output_path: Option<PathBuf>,
) -> Result<()> {
    let prover_input = rpc::fetch_prover_input(rpc_url, block_number).await?;

    let proof = prover_input.prove(&runtime, previous).await;
    runtime.close().await?;

    let proof = serde_json::to_vec(&proof?.intern)?;

    match proof_output_path {
        Some(p) => {
            if let Some(parent) = p.parent() {
                create_dir_all(parent)?;
            }

            let file_name = p
                .file_name()
                .with_context(|| format!("Unable to get a filename from {:?}", p))?;
            let mut f = File::create(file_name)?;
            f.write_all(&proof)?;
        }
        None => std::io::stdout().write_all(&proof)?,
    }

    Ok(())
}
