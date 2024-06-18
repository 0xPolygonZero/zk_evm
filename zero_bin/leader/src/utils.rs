use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::Result;

/// Retrieves the version of a specified package from the `Cargo.lock` file.
///
/// This function attempts to find the version of a package specified by
/// `package_name` by reading and parsing the `Cargo.lock` file. The
/// `Cargo.lock` file is expected to be located one directory level up from the
/// directory specified by the `CARGO_MANIFEST_DIR` environment variable. The
/// path may need adjustment depending on the structure of the project.
///
/// # Parameters
/// - `package_name`: The name of the package for which the version is being
///   retrieved.
///
/// # Returns
/// - `Ok(Some(String))`: If the package is found in the `Cargo.lock` file,
///   returns the version of the package.
/// - `Ok(None)`: If the package is not found in the `Cargo.lock` file, or if
///   the `Cargo.lock` file does not exist.
/// - `Err(_)`: If any error occurs during the execution, such as issues with
///   file paths, file access, reading, or parsing the `Cargo.lock` file.
///
/// # Examples
/// ```no_run
/// let version = get_package_version("my_package");
/// match version {
///     Ok(Some(ver)) => println!("Found version: {}", ver),
///     Ok(None) => println!("Package not found."),
///     Err(e) => println!("Error occurred: {}", e),
/// }
/// ```
///
/// # Errors
/// This function can return an `Err` result if:
/// - There is a problem finding, opening, or reading the `Cargo.lock` file.
/// - There is a failure in parsing the `Cargo.lock` file as TOML.
///
/// The function uses `?` to propagate errors upwards, so the exact nature of
/// the error will be indicated by the error value returned in the `Err` variant
/// of the `Result`.
pub(crate) fn get_package_version(package_name: &str) -> Result<Option<String>> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let zero_bin_path = Path::new(manifest_dir)
        .join("../") // Adjust the path according to your workspace structure
        .canonicalize()?;

    let cargo_lock_path = zero_bin_path.join("Cargo.lock");
    let cargo_lock_file = File::open(cargo_lock_path);
    if cargo_lock_file.is_err() {
        return Ok(None);
    }

    let mut cargo_lock_contents = String::new();
    BufReader::new(cargo_lock_file?).read_to_string(&mut cargo_lock_contents)?;

    let lockfile: toml::Value = toml::from_str(&cargo_lock_contents)?;
    if let Some(package) = lockfile["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|&p| p["name"].as_str() == Some(package_name))
    {
        let version = package["version"].as_str().unwrap();
        return Ok(Some(version.to_string()));
    }

    Ok(None)
}
