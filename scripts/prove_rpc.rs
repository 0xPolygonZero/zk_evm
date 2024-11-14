use alloy::{eips::BlockId, transports::http::reqwest::Url};
use anyhow::Result;
use clap::{arg, Args, ValueEnum, ValueHint};

#[derive(ValueEnum, Clone)]
enum RpcType {
    Jerigon,
    Native,
}

#[derive(ValueEnum, Clone)]
enum RunMode {
    /// Dummy proof is generated only. Useful for quickly testing decoding and
    /// all other non-proving logic.
    Test,
    /// The proof generated but is not verified.
    Prove,
    /// The proof generated and verified.
    Verify,
}

#[derive(Args)]
pub struct ProveRpcArgs {
    /// The node RPC URL.
    #[arg(short = 'u', value_hint = ValueHint::Url)]
    rpc_url: Url,
    /// The RPC type (jerigon or native).
    #[arg(short = 't', long)]
    rpc_type: RpcType,
    /// The start of the block range to prove (inclusive).
    #[arg(short = 's', long)]
    start_block: BlockId,
    /// The end of the block range to prove. If None, start_block-1 is used.
    #[arg(short = 'e', long)]
    checkpoint_block: Option<BlockId>,
    /// The end of the block range to prove (inclusive).
    #[arg(short = 'e', long)]
    end_block: Option<BlockId>,
    /// Backoff in milliseconds for retry requests
    #[arg(short = 'b', long, default_value_t = 0)]
    backoff: u64,
    /// The maximum number of retries
    #[arg(short = 'r', long, default_value_t = 0)]
    max_retries: u32,
    /// Whether to generate a proof and verify it or not.
    #[arg(short = 'm', long)]
    mode: RunMode,
}

pub fn prove_via_rpc(args: ProveRpcArgs) -> Result<()> {
    todo!()
}
