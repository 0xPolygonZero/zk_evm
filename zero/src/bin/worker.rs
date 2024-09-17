use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use paladin::runtime::WorkerRuntime;
use zero::prover_state::{
    cli::CliProverStateConfig, persistence::set_circuit_cache_dir_env_if_not_set,
};
use zero::{ops::register, tracing};

// TODO: https://github.com/0xPolygonZero/zk_evm/issues/302
//       this should probably be removed.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[derive(Parser)]
#[command(version = zero::version())]
struct Cli {
    #[clap(flatten)]
    paladin: paladin::config::Config,
    #[clap(flatten)]
    prover_state_config: CliProverStateConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    tracing::init();
    set_circuit_cache_dir_env_if_not_set()?;
    let args = Cli::parse();

    args.prover_state_config
        .into_prover_state_manager()
        .initialize()?;

    let runtime = WorkerRuntime::from_config(&args.paladin, register()).await?;
    runtime.main_loop().await?;

    Ok(())
}
