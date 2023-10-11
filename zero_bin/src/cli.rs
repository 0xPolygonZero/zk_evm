use clap::{Parser, ValueEnum};

#[derive(Parser)]
pub(crate) struct Cli {
    #[arg(short, long, value_enum, default_value_t = Mode::StdIo)]
    pub(crate) mode: Mode,
    #[arg(short, long, default_value_t = 8080)]
    pub(crate) port: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum, Default)]
pub(crate) enum Mode {
    #[default]
    StdIo,
    Http,
}
