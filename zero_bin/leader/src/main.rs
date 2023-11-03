use anyhow::Result;
use clap::Parser;
use cli::Mode;
use dotenvy::dotenv;
use ops::Ops;
use paladin::runtime::Runtime;

mod cli;
mod config;
mod http;
mod init;
mod prover_input;
mod rpc;
mod stdio;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    init::tracing();

    let args = cli::Cli::parse();
    let runtime = Runtime::from_config::<Ops>(&args.paladin_options).await?;

    match args.mode {
        Mode::StdIo => {
            stdio::stdio_main(runtime).await?;
        }
        Mode::Http => {
            http::http_main(runtime, args.port).await?;
        }
        Mode::Jerigon => {
            let rpc_url = args.rpc_url.expect("rpc-url is required in jerigon mode");
            let block_number = args
                .block_number
                .expect("block-number is required in jerigon mode");
            rpc::rpc_main(runtime, &rpc_url, block_number).await?;
        }
    }

    Ok(())
}
