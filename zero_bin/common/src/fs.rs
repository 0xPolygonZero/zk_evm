use std::fs::File;
use std::path::PathBuf;

use proof_gen::proof_types::GeneratedBlockProof;

pub fn generate_block_proof_file_name(directory: &Option<&str>, block_height: u64) -> PathBuf {
    let mut path = PathBuf::from(directory.unwrap_or(""));
    path.push(format!("b{}.zkproof", block_height));
    path
}

pub fn get_previous_proof(path: Option<PathBuf>) -> anyhow::Result<Option<GeneratedBlockProof>> {
    if path.is_none() {
        return Ok(None);
    }

    let path = path.unwrap();
    let file = File::open(path)?;
    let des = &mut serde_json::Deserializer::from_reader(&file);
    let proof: GeneratedBlockProof = serde_path_to_error::deserialize(des)?;
    Ok(Some(proof))
}
