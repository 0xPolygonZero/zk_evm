use anyhow::Result;
use clap::Parser;
use cli::Mode;
use dotenvy::dotenv;
use ops::Ops;
use paladin::runtime::Runtime;

mod cli;
mod http;
mod init;
mod prover_input;
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
    }

    Ok(())
}
