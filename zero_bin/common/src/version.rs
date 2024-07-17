pub fn print_version(
    evm_arithmetization_kernel_version: &str,
    rustc_commit_hash: &str,
    rustc_timestamp: &str,
) {
    println!(
        "evm_arithmetization Kernel Version: {}\nBuild Commit Hash: {}\nBuild Timestamp: {}",
        evm_arithmetization_kernel_version, rustc_commit_hash, rustc_timestamp
    )
}
