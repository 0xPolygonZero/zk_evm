use std::env;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use ops::register;
use paladin::runtime::WorkerRuntime;
use zero_bin_common::prover_state::{cli::CliProverStateConfig, persistence::set_circuit_cache_dir_env_if_not_set};
use zero_bin_common::version;

mod init;

// TODO: https://github.com/0xPolygonZero/zk_evm/issues/302
//       this should probably be removed.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser)]
struct Cli {
    #[clap(flatten)]
    paladin: paladin::config::Config,
    #[clap(flatten)]
    prover_state_config: CliProverStateConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--version".to_string()) {
        version::print_version(
            env!("EVM_ARITHMETIZATION_PKG_VER"),
            env!("VERGEN_RUSTC_COMMIT_HASH"),
            env!("VERGEN_BUILD_TIMESTAMP"),
        );
        return Ok(());
    }

    dotenv().ok();
    init::tracing();
    set_circuit_cache_dir_env_if_not_set()?;
    let args = Cli::parse();

    args.prover_state_config
        .into_prover_state_manager()
        .initialize()?;

    let runtime = WorkerRuntime::from_config(&args.paladin, register()).await?;
    runtime.main_loop().await?;

    Ok(())
}
