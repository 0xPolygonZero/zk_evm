use anyhow::Context as _;
use vergen::{BuildBuilder, Emitter, RustcBuilder};

fn main() -> anyhow::Result<()> {
    let build_timestamp = BuildBuilder::default().build_timestamp(true).build()?;
    let rust_commit_hash = RustcBuilder::default().commit_hash(true).build()?;

    Emitter::default()
        .add_instructions(&build_timestamp)?
        .add_instructions(&rust_commit_hash)?
        .emit()?;

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
        "cargo::rustc-env=EVM_ARITHMETIZATION_PKG_VER={}.{}.x",
        // patch version change should not prompt circuits regeneration
        version.major,
        version.minor
    );

    Ok(())
}
