use std::env::{self};

use anyhow::Result;
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use ops::register;
use paladin::runtime::WorkerRuntime;
use zero_bin_common::prover_state::cli::CliProverStateConfig;

mod init;

// TODO: https://github.com/0xPolygonZero/zk_evm/issues/302
//       this should probably be removed.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

const EVM_ARITH_VER_KEY: &str = "EVM_ARITHMETIZATION_PKG_VER";
const VERGEN_BUILD_TIMESTAMP: &str = "VERGEN_BUILD_TIMESTAMP";
const VERGEN_RUSTC_COMMIT_HASH: &str = "VERGEN_RUSTC_COMMIT_HASH";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
    #[clap(flatten)]
    paladin: paladin::config::Config,
    #[clap(flatten)]
    prover_state_config: CliProverStateConfig,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    Version {},
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    let args = Cli::parse();

    if env::var_os(EVM_ARITH_VER_KEY).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                EVM_ARITH_VER_KEY,
                // see build.rs
                env!("EVM_ARITHMETIZATION_PACKAGE_VERSION"),
            );
        }
    }
    if env::var_os(VERGEN_BUILD_TIMESTAMP).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_BUILD_TIMESTAMP,
                // see build.rs
                env!("VERGEN_BUILD_TIMESTAMP"),
            );
        }
    }
    if env::var_os(VERGEN_RUSTC_COMMIT_HASH).is_none() {
        // Safety:
        // - we're early enough in main that nothing else should race
        unsafe {
            env::set_var(
                VERGEN_RUSTC_COMMIT_HASH,
                // see build.rs
                env!("VERGEN_RUSTC_COMMIT_HASH"),
            );
        }
    }

    if let Some(Command::Version {}) = args.command {
        println!(
            "Evm Arithmetization package version: {}",
            env::var(EVM_ARITH_VER_KEY)?
        );
        println!("Build Commit Hash: {}", env::var(VERGEN_RUSTC_COMMIT_HASH)?);
        println!("Build Timestamp: {}", env::var(VERGEN_BUILD_TIMESTAMP)?);
        return Ok(());
    }

    args.prover_state_config
        .into_prover_state_manager()
        .initialize()?;

    let runtime = WorkerRuntime::from_config(&args.paladin, register()).await?;
    runtime.main_loop().await?;

    Ok(())
}
