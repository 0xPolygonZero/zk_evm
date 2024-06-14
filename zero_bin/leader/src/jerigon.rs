use std::io::Write;
use std::path::PathBuf;

use alloy::providers::RootProvider;
use anyhow::Result;
use common::block_interval::BlockInterval;
use common::fs::generate_block_proof_file_name;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use tracing::{error, info, warn};

#[derive(Debug, Default)]
pub struct ProofParams {
    pub checkpoint_block_number: u64,
    pub previous_proof: Option<GeneratedBlockProof>,
    pub proof_output_dir: Option<PathBuf>,
    pub save_inputs_on_error: bool,
    pub keep_intermediate_proofs: bool,
}

/// The main function for the jerigon mode.
pub(crate) async fn jerigon_main(
    runtime: Runtime,
    rpc_url: &str,
    block_interval: BlockInterval,
    mut params: ProofParams,
) -> Result<()> {
    let prover_input = rpc::prover_input(
        RootProvider::new_http(rpc_url.parse()?),
        block_interval,
        params.checkpoint_block_number.into(),
    )
    .await?;

    if cfg!(feature = "test_only") {
        info!("All proof witnesses have been generated successfully.");
    } else {
        info!("All proofs have been generated successfully.");
    }

    // If `keep_intermediate_proofs` is not set we only keep the last block
    // proof from the interval. It contains all the necessary information to
    // verify the whole sequence.
    let proved_blocks = prover_input
        .prove(
            &runtime,
            params.previous_proof.take(),
            params.save_inputs_on_error,
            params.proof_output_dir.clone(),
        )
        .await;
    runtime.close().await?;
    let proved_blocks = proved_blocks?;

    if params.keep_intermediate_proofs {
        if params.proof_output_dir.is_some() {
            // All proof files (including intermediary) are written to disk and kept
            warn!("Skipping cleanup, intermediate proof files are kept");
        } else {
            // Output all proofs to stdout
            std::io::stdout().write_all(&serde_json::to_vec(
                &proved_blocks
                    .into_iter()
                    .filter_map(|(_, block)| block)
                    .collect::<Vec<_>>(),
            )?)?;
        }
    } else if let Some(proof_output_dir) = params.proof_output_dir.as_ref() {
        // Remove intermediary proof files
        proved_blocks
            .into_iter()
            .rev()
            .skip(1)
            .map(|(block_number, _)| {
                generate_block_proof_file_name(&proof_output_dir.to_str(), block_number)
            })
            .for_each(|path| {
                if let Err(e) = std::fs::remove_file(path) {
                    error!("Failed to remove intermediate proof file: {e}");
                }
            });
    } else {
        // Output only last proof to stdout
        if let Some(last_block) = proved_blocks
            .into_iter()
            .filter_map(|(_, block)| block)
            .last()
        {
            std::io::stdout().write_all(&serde_json::to_vec(&last_block)?)?;
        }
    }

    Ok(())
}
