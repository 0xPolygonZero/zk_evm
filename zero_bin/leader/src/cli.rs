use std::path::PathBuf;

use clap::{Parser, ValueEnum, ValueHint};
use paladin::config::Runtime;

#[derive(Parser)]
pub(crate) struct Cli {
    /// The input mode. If `std-io`, the input is read from stdin. If `http`,
    /// the input is read from HTTP requests. If `jerigon`, the input is
    /// read from the `debug_traceBlockByNumber` and `eth_getBlockByNumber`
    /// RPC methods from Jerigon.
    #[arg(short, long, value_enum, default_value_t = Mode::StdIo)]
    pub(crate) mode: Mode,
    /// The port to listen on when using the `http` mode.
    #[arg(short, long, default_value_t = 8080)]
    pub(crate) port: u16,
    /// The directory to which output should be written (`http` mode only).
    #[arg(short, long, required_if_eq("mode", "http"), value_hint = ValueHint::DirPath)]
    pub(crate) output_dir: Option<PathBuf>,
    /// The RPC URL to use when using the `jerigon` mode.
    #[arg(long, required_if_eq("mode", "jerigon"), value_hint = ValueHint::Url)]
    pub(crate) rpc_url: Option<String>,
    /// The block number to use when using the `jerigon` mode.
    #[arg(short, long, required_if_eq("mode", "jerigon"))]
    pub(crate) block_number: Option<u64>,
    /// Specifies the paladin runtime to use.
    #[arg(long, short, value_enum, default_value_t = Runtime::Amqp)]
    pub(crate) runtime: Runtime,
    /// Specifies the number of worker threads to spawn (in memory runtime
    /// only).
    #[arg(long, short)]
    pub num_workers: Option<usize>,
    /// The previous proof output.
    #[arg(long, short = 'f')]
    pub previous_proof: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Default)]
pub(crate) enum Mode {
    #[default]
    StdIo,
    Http,
    Jerigon,
}
