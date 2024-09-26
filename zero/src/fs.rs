use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use tokio::io::AsyncWriteExt;

use crate::proof_types::{GeneratedBlockProof, WritableProof};

pub fn generate_block_proof_file_name(
    directory: &Option<&str>,
    block_height: Option<u64>,
    extra_info: &Option<String>,
) -> PathBuf {
    let mut path = PathBuf::from(directory.unwrap_or(""));
    let mut filename = if let Some(height) = block_height {
        format!("b{}", height)
    } else {
        "".to_string()
    };
    if let Some(info) = extra_info {
        filename = filename + info;
    }
    path.push(filename + ".zkproof");
    path
}

pub fn get_previous_proof(path: Option<PathBuf>) -> anyhow::Result<Option<GeneratedBlockProof>> {
    if path.is_none() {
        return Ok(None);
    }

    let path = path.unwrap();
    let file = File::open(path)?;
    let des = &mut serde_json::Deserializer::from_reader(&file);
    let proof: Vec<GeneratedBlockProof> = serde_path_to_error::deserialize(des)?;
    // Individual proofs are serialized as vector to match other output formats.
    if proof.len() != 1 {
        return Err(anyhow!("Invalid proof format, expected vector of generated block proofs with a single element."));
    }

    Ok(Some(proof[0].to_owned()))
}

/// Write the proof to the `output_dir` directory.
pub async fn write_proof_to_dir<P: WritableProof>(
    output_dir: &Path,
    proof: P,
    extra_info: Option<String>,
) -> anyhow::Result<()> {
    // Check if output directory exists, and create one if it doesn't.
    if !output_dir.exists() {
        tracing::info!("Created output directory {:?}", output_dir.display());
        std::fs::create_dir(output_dir)?;
    }

    let block_proof_file_path =
        generate_block_proof_file_name(&output_dir.to_str(), proof.block_height(), &extra_info);

    // Serialize as a single element array to match the expected format.
    let proof_serialized = serde_json::to_vec(&vec![proof])?;

    if let Some(parent) = block_proof_file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut f = tokio::fs::File::create(block_proof_file_path.clone()).await?;
    f.write_all(&proof_serialized)
        .await
        .context("Failed to write proof to disk")?;

    tracing::info!(
        "Successfully wrote to disk proof file {}",
        block_proof_file_path.display()
    );
    Ok(())
}
