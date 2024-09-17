use anyhow::Context as _;
use vergen_git2::{BuildBuilder, Emitter, Git2Builder};

fn main() -> anyhow::Result<()> {
    Emitter::new()
        .add_instructions(&BuildBuilder::default().build_timestamp(true).build()?)?
        .add_instructions(&Git2Builder::default().describe(true, true, None).build()?)?
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
