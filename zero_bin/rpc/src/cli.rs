use clap::{Parser, Subcommand, ValueHint};

#[derive(Parser)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Fetch and generate prover input from the RPC endpoint
    Fetch {
        /// The RPC URL
        #[arg(short = 'u', long, value_hint = ValueHint::Url)]
        rpc_url: String,
        /// The block number
        #[arg(short, long)]
        block_number: u64,
        /// The checkpoint block number
        #[arg(short, long, default_value_t = 0)]
        checkpoint_block_number: u64,
    },
}
