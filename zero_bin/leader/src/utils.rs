use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::Result;

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
