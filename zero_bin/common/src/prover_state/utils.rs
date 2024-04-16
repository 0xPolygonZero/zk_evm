use std::fs::{self, File};
use std::hash::Hasher;
use std::io::{Read, Write};
use std::path::Path;

use seahash::SeaHasher;
use tracing::{info, warn};

use super::persistence::CIRCUITS_FOLDER;

/// Checks the consistency of circuits code by comparing a computed hash
/// derived from the provided array of circuit code hashes against a reference
/// hash stored in a designated file within the circuits folder. This function
/// performs several actions based on this comparison:
///
/// - If the computed aggregate hash differs from the stored hash, or if the
///   hash file does not exist, the function will delete the existing circuits
///   folder (if it exists), recreate it, and then write the new computed hash
///   into the hash file.
///
/// - If the computed hash matches the stored hash, indicating no changes in the
///   circuits code, the function takes no action.
///
/// This process ensures that the stored hash always reflects the current state
/// of the circuits code, providing a mechanism for detecting changes and
/// maintaining consistency.
///
/// # Parameters
///
/// * `circuits_hashes` - A dynamic number of `Vec<u8>` arguments representing
///   circuit code hashes.
///
/// # Side Effects
///
/// - May delete and recreate the circuits folder.
/// - May modify or create a file within the circuits folder to store the latest
///   hash.
pub(crate) fn pkg_consistency_check<I, T>(circuits_hashes: I)
where
    I: IntoIterator<Item = T>,
    T: AsRef<[u8]>,
{
    let mut hasher = SeaHasher::new();
    for hash in circuits_hashes {
        hasher.write(hash.as_ref());
    }
    let hash = hasher.finish();

    let hash_file_path = Path::new(CIRCUITS_FOLDER).join("circuits_consistency_hash");

    // Check if the circuits folder exists
    match fs::metadata(CIRCUITS_FOLDER) {
        Ok(_) => {
            // Circuits folder exists, check the hash file
            let mut existing_hash = String::new();
            if let Ok(mut hash_file) = File::open(&hash_file_path) {
                // If the hash file exists and can be read, compare the hash
                if hash_file.read_to_string(&mut existing_hash).is_ok()
                    && existing_hash == hash.to_string()
                {
                    // Hashes are the same, do nothing
                    return;
                }
            } else {
                warn!("Unable to read circuits consistency hash file");
            }

            // Hashes differ or hash file cannot be read, delete the folder
            if fs::remove_dir_all(CIRCUITS_FOLDER).is_err() {
                panic!("Failed to delete circuits storage folder");
            }
        }
        Err(_) => {
            info!(
                "Initializing circuits storage folder with new consistency hash: {}",
                hash
            );
        }
    }

    // Recreate the circuits folder and write the new hash
    if fs::create_dir(CIRCUITS_FOLDER).is_ok() {
        if let Ok(mut hash_file) = File::create(&hash_file_path) {
            // Ignore errors in writing the hash
            let _ = hash_file.write_all(hash.to_string().as_bytes());
        }
    } else {
        panic!("Failed to create circuits storage folder");
    }
}
