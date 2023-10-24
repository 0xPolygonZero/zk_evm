use clap::{Parser, ValueEnum};
use paladin::config::Config;

#[derive(Parser)]
pub(crate) struct Cli {
    /// The input mode. If `stdio`, the input is read from stdin. If `http`, the
    /// input is read from HTTP requests.
    #[arg(short, long, value_enum, default_value_t = Mode::StdIo)]
    pub(crate) mode: Mode,
    /// The port to listen on when using the `http` mode.
    #[arg(short, long, default_value_t = 8080)]
    pub(crate) port: u16,
    #[command(flatten)]
    pub paladin_options: Config,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Default)]
pub(crate) enum Mode {
    #[default]
    StdIo,
    Http,
}
