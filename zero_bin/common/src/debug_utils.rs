use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Error as SerdeError;
use thiserror::Error;

const DEBUG_FOLDER: &str = "./debug";

/// Ensures that the specified directory exists on the filesystem.
///
/// This function checks if the directory at `folder_path` exists. If not, it
/// attempts to create the directory. It returns an error if the path is not a
/// directory or if there are issues accessing or creating the directory.
///
/// # Parameters
/// * `folder_path` - A reference to a `Path` that specifies the directory to
///   check or create.
///
/// # Returns
/// * `Ok(())` - The directory exists or was successfully created.
/// * `Err(io::Error)` - The path is not a directory, or there was a problem
///   accessing or creating the directory.
fn ensure_directory_exists(folder_path: &Path) -> io::Result<()> {
    match fs::metadata(folder_path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                Ok(()) // The directory already exists
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "The path exists but is not a directory",
                ))
            }
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                // Directory does not exist, try to create it
                fs::create_dir(folder_path)
            } else {
                // Re-throw the error if it's not a 'NotFound' error
                Err(e)
            }
        }
    }
}

/// An error type for save debug input information.
#[derive(Error, Debug)]
pub enum SaveInputError {
    #[error("failed to create directory '{0}'")]
    CreateDirectoryError(PathBuf, #[source] io::Error),

    #[error("failed to create file '{0}'")]
    CreateFileError(PathBuf, #[source] io::Error),

    #[error("failed to serialize inputs")]
    SerializationError(#[source] SerdeError),

    #[error("failed to write to file '{0}'")]
    WriteToFileError(PathBuf, #[source] io::Error),
}

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
pub fn save_inputs_to_disk<T: Serialize>(
    file_name: String,
    inputs: T,
) -> Result<(), SaveInputError> {
    let debug_folder = Path::new(DEBUG_FOLDER);
    let input_file_path = debug_folder.join(file_name);

    // Ensure the DEBUG_FOLDER exists
    ensure_directory_exists(debug_folder)
        .map_err(|e| SaveInputError::CreateDirectoryError(debug_folder.to_path_buf(), e))?;

    let mut file = File::create(&input_file_path)
        .map_err(|e| SaveInputError::CreateFileError(input_file_path.clone(), e))?;

    // Serialize the entire collection to a pretty JSON string
    let all_inputs_str =
        serde_json::to_string_pretty(&inputs).map_err(SaveInputError::SerializationError)?;

    // Write the serialized data to the file
    file.write_all(all_inputs_str.as_bytes())
        .map_err(|e| SaveInputError::WriteToFileError(input_file_path, e))?;

    Ok(())
}
