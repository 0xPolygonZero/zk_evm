use anyhow::Result;
use clap::Parser;
use common::prover_state::{cli::CliProverStateConfig, set_prover_state_from_config};
use dotenvy::dotenv;
use ops::Ops;
use paladin::runtime::WorkerRuntime;
use tracing::warn;

mod init;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(flatten)]
    paladin: paladin::config::Config,
    #[clap(flatten)]
    prover_state_config: CliProverStateConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();
    let args = Cli::parse();

    if set_prover_state_from_config(args.prover_state_config.into()).is_err() {
        warn!("prover state already set. check the program logic to ensure it is only set once");
    }

    let runtime: WorkerRuntime<Ops> = WorkerRuntime::from_config(&args.paladin).await?;
    runtime.main_loop().await?;

    Ok(())
}
