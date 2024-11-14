use std::{
    env::set_var,
    fs::create_dir_all,
    path::{Path, PathBuf},
};

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
    /// Dummy proof is generated. Useful for quickly testing decoding and
    /// all other non-proving logic.
    Test,
    /// The proof is generated but is not verified.
    Prove,
    /// The proof is generated and verified.
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
    #[arg(short = 'c', long)]
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
    /// The batch size for block fetching.
    #[arg(long, default_value_t = 8)]
    block_batch_size: u32,
    /// The directory to output the proof files. If it does not exist, it will
    /// recursively be created.
    #[arg(short = 'o', long, value_hint = ValueHint::DirPath, default_value = ".")]
    output_dir: PathBuf,
}

pub fn prove_via_rpc(args: ProveRpcArgs) -> Result<()> {
    // Set rustc environment variables.
    set_var("RUST_MIN_STACK", "33554432");
    set_var("RUST_BACKTRACE", "1");
    set_var("RUST_LOG", "info");
    // Script users are running locally, and might benefit from extra perf.
    // See also .cargo/config.toml.
    set_var("RUSTFLAGS", "-C target-cpu=native -Zlinker-features=-lld");

    // Handle optional block inputs.
    let start_block = args.start_block;
    let end_block = args.end_block.unwrap_or(start_block);
    let checkpoint_block = match args.checkpoint_block {
        Some(checkpoint_block) => checkpoint_block,
        // No checkpoint block specified, infer from start block.
        None => match start_block {
            // Infer the checkpoint block from the start block.
            BlockId::Number(start_block) => BlockId::from(start_block.as_number().unwrap() - 1u64),
            // Cannot infer the checkpoint block from a hash.
            BlockId::Hash(_) => {
                anyhow::bail!("Must specify checkpoint block if start block is a hash.")
            }
        },
    };

    // Create the output directory if it does not exist.
    let proof_output_dirpath = Path::new(&args.output_dir);
    if !proof_output_dirpath.exists() {
        create_dir_all(proof_output_dirpath)?;
    }
    let output_log_path =
        proof_output_dirpath.join(format!("b{}_{}.log", args.start_block, end_block));

    todo!()
}
