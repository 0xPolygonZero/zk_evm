use std::path::PathBuf;

pub fn generate_block_proof_file_name(directory: &Option<&str>, block_height: u64) -> PathBuf {
    let mut path = PathBuf::from(directory.unwrap_or(""));
    path.push(format!("b{}.zkproof", block_height));
    path
}
