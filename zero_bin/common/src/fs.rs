use std::fs::File;
use std::path::PathBuf;

use anyhow::anyhow;
use evm_arithmetization::proof::PublicValues;
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
    let proof: Vec<GeneratedBlockProof> = serde_path_to_error::deserialize(des)?;
    // Individual proofs are serialized as vector to match other output formats.
    if proof.len() != 1 {
        return Err(anyhow!("Invalid proof format."));
    }

    std::fs::write(
        "inputs.json",
        serde_json::to_string(&PublicValues::from_public_inputs(
            &proof[0].intern.public_inputs,
        ))
        .unwrap(),
    )
    .unwrap();

    Ok(Some(proof[0].to_owned()))
}
