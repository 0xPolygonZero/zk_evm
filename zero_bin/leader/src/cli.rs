use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueHint};
use paladin::config::Runtime;

#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,

    #[clap(flatten)]
    pub(crate) runtime: RuntimeGroup,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Reads input from stdin and writes output to stdout.
    Stdio {
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
    },
    /// Reads input from a Jerigon node and writes output to stdout.
    Jerigon {
        // The Jerigon RPC URL.
        #[arg(long, short = 'u', value_hint = ValueHint::Url)]
        rpc_url: String,
        /// The block number for which to generate a proof.
        #[arg(short, long)]
        block_number: u64,
        /// The previous proof output.
        #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
        previous_proof: Option<PathBuf>,
    },
    /// Reads input from HTTP and writes output to a directory.
    Http {
        /// The port on which to listen.
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        /// The directory to which output should be written.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        output_dir: PathBuf,
    },
}

#[derive(Args)]
pub(crate) struct RuntimeGroup {
    /// Specifies the number of worker threads to spawn (in memory runtime
    /// only).
    #[arg(long, short)]
    pub(crate) num_workers: Option<usize>,
    /// Specifies the paladin runtime mode.
    #[arg(long, short, value_enum, default_value_t = Runtime::Amqp)]
    pub(crate) runtime: Runtime,
    /// Specifies the URI for the AMQP broker (AMQP runtime only).
    #[arg(long, env = "AMQP_URI", value_hint = ValueHint::Url, required_if_eq("runtime", "amqp"))]
    pub amqp_uri: Option<String>,
}
