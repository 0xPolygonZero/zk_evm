pub fn print_version(
    evm_arithmetization_package_version: &str,
    rustc_commit_hash: &str,
    rustc_timestamp: &str,
) {
    println!(
        "Evm Arithmetization package version: {:?}",
        evm_arithmetization_package_version
    );
    println!("Build Commit Hash: {:?}", rustc_commit_hash);
    println!("Build Timestamp: {:?}", rustc_timestamp);
}
