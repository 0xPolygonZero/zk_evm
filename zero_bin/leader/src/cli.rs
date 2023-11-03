use clap::{Parser, ValueEnum};
use paladin::config::Config;

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
    /// The RPC URL to use when using the `jerigon` mode.
    #[arg(long, required_if_eq("mode", "jerigon"))]
    pub(crate) rpc_url: Option<String>,
    /// The block number to use when using the `jerigon` mode.
    #[arg(short, long, required_if_eq("mode", "jerigon"))]
    pub(crate) block_number: Option<u64>,
    #[command(flatten)]
    pub(crate) paladin_options: Config,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Default)]
pub(crate) enum Mode {
    #[default]
    StdIo,
    Http,
    Jerigon,
}
