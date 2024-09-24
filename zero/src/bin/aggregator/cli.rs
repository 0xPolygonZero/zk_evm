use clap::{Parser, Subcommand};
use zero::prover::cli::CliProverConfig;

/// zero-bin leader config
#[derive(Parser)]
#[command(version = zero::version(), propagate_version = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    /// Boolean indicating weather to wrap or aggregate block proofs.
    /// Defaults to `false = aggregate`.
    #[arg(short, long, default_value_t = false)]
    pub(crate) wrap: bool,

    #[clap(flatten)]
    pub(crate) paladin: paladin::config::Config,

    #[clap(flatten)]
    pub(crate) prover_config: CliProverConfig,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Reads input from stdin and writes output to stdout.
    Stdio,
    /// Reads input from a node rpc and writes output to stdout.
    Rpc,
    /// Reads input from HTTP and writes output to a directory.
    Http,
}
