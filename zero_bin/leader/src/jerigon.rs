use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::PathBuf,
};

use alloy::providers::RootProvider;
use anyhow::Result;
use common::block_interval::BlockInterval;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;

/// The main function for the jerigon mode.
pub(crate) async fn jerigon_main(
    runtime: Runtime,
    rpc_url: &str,
    block_interval: BlockInterval,
    checkpoint_block_number: u64,
    previous_proof: Option<GeneratedBlockProof>,
    proof_output_dir_opt: Option<PathBuf>,
    save_inputs_on_error: bool,
) -> Result<()> {
    let prover_input = rpc::prover_input(
        RootProvider::new_http(rpc_url.parse()?),
        block_interval,
        checkpoint_block_number.into(),
    )
    .await?;

    let block_proofs = prover_input
        .prove(&runtime, previous_proof, save_inputs_on_error)
        .await?;
    runtime.close().await?;

    for block_proof in block_proofs {
        let block_proof_str = serde_json::to_vec(&block_proof)?;
        write_proof(
            block_proof_str,
            proof_output_dir_opt.clone().map(|mut path| {
                path.push(format!("b{}.zkproof", block_proof.b_height));
                path
            }),
        )?;
    }
    Ok(())
}

fn write_proof(proof: Vec<u8>, proof_output_dir_opt: Option<PathBuf>) -> Result<()> {
    match proof_output_dir_opt {
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
