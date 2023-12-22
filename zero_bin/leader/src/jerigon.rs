use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::PathBuf,
};

use anyhow::Result;
use paladin::runtime::Runtime;
use plonky_block_proof_gen::types::PlonkyProofIntern;

/// The main function for the jerigon mode.
pub(crate) async fn jerigon_main(
    runtime: Runtime,
    rpc_url: &str,
    block_number: u64,
    checkpoint_block_number: u64,
    previous: Option<PlonkyProofIntern>,
    proof_output_path_opt: Option<PathBuf>,
) -> Result<()> {
    let prover_input = rpc::fetch_prover_input(rpc::FetchProverInputRequest {
        rpc_url,
        block_number,
        checkpoint_block_number,
    })
    .await?;

    let proof = prover_input.prove(&runtime, previous).await;
    runtime.close().await?;

    let proof = serde_json::to_vec(&proof?.intern)?;
    write_proof(proof, proof_output_path_opt)
}

fn write_proof(proof: Vec<u8>, proof_output_path_opt: Option<PathBuf>) -> Result<()> {
    match proof_output_path_opt {
        Some(p) => {
            if let Some(parent) = p.parent() {
                create_dir_all(parent)?;
            }

            let mut f = File::create(p)?;
            f.write_all(&proof)?;
        }
        None => std::io::stdout().write_all(&proof)?,
    }

    Ok(())
}
