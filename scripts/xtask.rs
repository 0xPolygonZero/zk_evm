//! General purpose scripts for development

mod outdated;

use anyhow::Result;
use clap::Parser;
use outdated::list_outdated_deps;

#[derive(Parser)]
enum Args {
    /// Run `cargo-outdated`, printing warnings compatible with GitHub's CI.
    ///
    /// If a direct dependency listed in our Cargo.lock is behind the latest
    /// available on crates-io, a warning will be emitted.
    ///
    /// Note that we only warn on our _direct_ dependencies,
    /// not the entire supply chain.
    Outdated,
}

fn main() -> Result<()> {
    match Args::parse() {
        Args::Outdated => list_outdated_deps(),
    }
}
