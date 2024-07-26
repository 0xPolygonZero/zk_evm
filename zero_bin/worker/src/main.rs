use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use log::{error, info};
use ops::register;
use paladin::runtime::WorkerRuntime;
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task;
use zero_bin_common::prover_state::cli::CliProverStateConfig;

mod init;

// TODO: https://github.com/0xPolygonZero/zk_evm/issues/302
//       this should probably be removed.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

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

    let mut sigterm =
        signal(SignalKind::terminate()).expect("Failed to create SIGTERM signal handler");

    let args = Cli::parse();

    args.prover_state_config
        .into_prover_state_manager()
        .initialize()?;

    let runtime = WorkerRuntime::from_config(&args.paladin, register()).await?;
    //const IPC_ROUTING_KEY: Uuid = Uuid::max(); // copied over from paladin-core's
    // WorkerRuntime code in src/runtime/mod.rs let cancel_message: WorkerIpc =
    // WorkerIpc::ExecutionError {    routing_key: IPC_ROUTING_KEY,
    //};
    //let runtime_clone = runtime.clone();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let sigterm_task = task::spawn(async move {
        //let runtime_canceler = runtime_clone.get_ipc_sender().await.unwrap();
        sigterm.recv().await;
        info!("Received SIGTERM, terminating...");
        //runtime_canceler.publish(&cancel_message).await.unwrap();
        r.store(false, Ordering::SeqCst);
    });
    let runtime_task = task::spawn(async move {
        match runtime.main_loop(Some(running)).await {
            Ok(()) => info!("Worker main loop ended..."),
            Err(err) => error!("Error occured with the runtime: {}", err),
        }
    });

    info!("starting the main loop");
    select! {
        _ = sigterm_task => {
            info!("Graceful shutdown attempted...");
        },
        _ = runtime_task => {
            info!("Runtime ended without SIGTERM...");
        }
    }
    info!("Graceful shutdown worked!");

    Ok(())
}
