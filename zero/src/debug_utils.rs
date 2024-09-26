use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use evm_arithmetization::generation::DebugOutputTries;
use serde::{Deserialize, Serialize};

const DEBUG_FOLDER: &str = "./debug";

/// Serializes a collection of inputs to a pretty-printed JSON format and saves
/// them to a file.
///
/// # Arguments
///
/// * `file_name` - The name of the file (including the extension) where the
///   serialized data will be saved.
/// * `inputs` - A collection of items to be serialized. Each item in the
///   collection must implement the `Serialize` trait.
///
/// # Returns
///
/// This function returns a `Result<(), std::io::Error>` indicating the
/// operation's success or failure.
pub fn save_inputs_to_disk<T: Serialize>(file_name: String, inputs: T) -> anyhow::Result<()> {
    let debug_folder = Path::new(DEBUG_FOLDER);

    // Check if output directory exists, and create one if it doesn't.
    if !debug_folder.exists() {
        fs::create_dir(debug_folder)?;
    }

    let input_file_path = debug_folder.join(file_name);
    let mut file = File::create(&input_file_path)?;

    // Serialize the entire collection to a pretty JSON string
    let all_inputs_str = serde_json::to_string_pretty(&inputs)?;

    // Write the serialized data to the file
    file.write_all(all_inputs_str.as_bytes())?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ErrorTrieFile {
    pub error: String,
    pub block_number: u64,
    pub batch_index: usize,
    pub tries: DebugOutputTries,
}

pub fn generate_trie_debug_file_name(block_number: u64, batch_index: usize) -> String {
    format!("b{}_batch{}_error_tries.data", block_number, batch_index)
}

pub fn save_tries_to_disk(
    err: &str,
    block_number: u64,
    batch_index: usize,
    tries: &DebugOutputTries,
) -> anyhow::Result<()> {
    let output_dir = PathBuf::from(DEBUG_FOLDER);

    // Check if output directory exists, and create one if it doesn't.
    if !output_dir.exists() {
        fs::create_dir(output_dir.clone())?;
    }

    let mut tries_debug_file_path = output_dir;
    tries_debug_file_path.push(generate_trie_debug_file_name(block_number, batch_index));

    let simulation_error_str = serde_json::to_string(&ErrorTrieFile {
        error: err.to_string(),
        block_number,
        batch_index,
        tries: tries.clone(),
    })
    .context("unable to serialize simulation error to save tries")?;
    fs::write(tries_debug_file_path, simulation_error_str)
        .expect("unable to write simulation error to file");
    Ok(())
}

pub fn load_tries_from_disk(
    block_number: u64,
    batch_index: usize,
) -> anyhow::Result<ErrorTrieFile> {
    let mut tries_debug_file_path = PathBuf::from(DEBUG_FOLDER);
    tries_debug_file_path.push(generate_trie_debug_file_name(block_number, batch_index));
    let file = File::open(tries_debug_file_path)?;
    let data: ErrorTrieFile = serde_json::from_reader(file)?;
    Ok(data)
}
