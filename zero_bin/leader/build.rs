use anyhow::Context as _;
fn main() -> anyhow::Result<()> {
    let meta = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("failed to probe cargo-metadata")?;
    let version = &meta
        .packages
        .iter()
        .find(|it| it.name == "evm_arithmetization")
        .context("couldn't find evm_arithmetization package")?
        .version;
    println!(
        "cargo::rustc-env=EVM_ARITHMETIZATION_PACKAGE_VERSION={}.{}.x",
        // patch version change should not prompt circuits regeneration
        version.major,
        version.minor
    );
    Ok(())
}
