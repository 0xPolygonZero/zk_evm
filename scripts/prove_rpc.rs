use std::{
    env::set_var,
    fmt::Display,
    fs::create_dir_all,
    path::{Path, PathBuf},
};

use alloy::{eips::BlockId, transports::http::reqwest::Url};
use anyhow::Result;
use clap::{arg, Args, ValueEnum, ValueHint};

use crate::process::Process;

#[derive(ValueEnum, Clone)]
enum RpcType {
    Jerigon,
    Native,
}

impl Display for RpcType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcType::Jerigon => write!(f, "jerigon"),
            RpcType::Native => write!(f, "native"),
        }
    }
}

#[derive(ValueEnum, Copy, Clone)]
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
    #[arg(value_hint = ValueHint::Url)]
    rpc_url: Url,
    /// The RPC type (jerigon or native).
    #[arg()]
    rpc_type: RpcType,
    /// Whether to generate a proof and verify it or not.
    #[arg()]
    mode: RunMode,
    /// The start of the block range to prove (inclusive).
    #[arg()]
    start_block: BlockId,
    /// The end of the block range to prove. If None, start_block-1 is used.
    #[arg(short = 'c', long)]
    checkpoint_block: Option<BlockId>,
    /// The end of the block range to prove (inclusive).
    #[arg(short = 'e', long)]
    end_block: Option<BlockId>,
    /// Backoff in milliseconds for retry requests.
    #[arg(short = 'b', long, default_value_t = 0)]
    backoff: u64,
    /// The maximum number of retries.
    #[arg(short = 'r', long, default_value_t = 7)]
    max_retries: u32,
    /// The batch size for block fetching.
    #[arg(long, default_value_t = 8)]
    block_batch_size: u32,
    /// The directory to output the proof files. If it does not exist, it will
    /// recursively be created.
    #[arg(short = 'o', long, value_hint = ValueHint::DirPath, default_value = ".")]
    output_dir: PathBuf,
}

/// Run leader binary to prove a block range via RPC.
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
    // Set file handle limit.
    const RECOMMENDED_FILE_LIMIT: isize = 8192;
    if !sysinfo::set_open_files_limit(RECOMMENDED_FILE_LIMIT) {
        eprintln!("WARNING: Unable to set file descriptor limit to recommended value: {RECOMMENDED_FILE_LIMIT}.");
    }

    // Construct common args used for all run modes.
    let leader_args = &[
        "--runtime=in-memory",
        "--load-strategy=on-demand",
        "--proof-output-dir",
        proof_output_dirpath.to_str().unwrap(),
        "--block-batch-size",
        &args.block_batch_size.to_string(),
        "rpc",
        "--rpc-type",
        &args.rpc_type.to_string(),
        "--rpc-url",
        args.rpc_url.as_ref(),
        "--start-block",
        &block_string(start_block),
        "--checkpoint-block",
        &block_string(checkpoint_block),
        "--end-block",
        &block_string(end_block),
        "--backoff",
        &args.backoff.to_string(),
        "--max-retries",
        &args.max_retries.to_string(),
    ];
    let cmd_args = command_args(args.mode, leader_args);

    // Run the appropriate command based on the run mode.
    match args.mode {
        RunMode::Test => {
            set_var("ARITHMETIC_CIRCUIT_SIZE", "16..21");
            set_var("BYTE_PACKING_CIRCUIT_SIZE", "8..21");
            set_var("CPU_CIRCUIT_SIZE", "8..21");
            set_var("KECCAK_CIRCUIT_SIZE", "4..20");
            set_var("KECCAK_SPONGE_CIRCUIT_SIZE", "8..17");
            set_var("LOGIC_CIRCUIT_SIZE", "4..21");
            set_var("MEMORY_CIRCUIT_SIZE", "17..24");
            set_var("MEMORY_BEFORE_CIRCUIT_SIZE", "16..23");
            set_var("MEMORY_AFTER_CIRCUIT_SIZE", "7..23");

            Process::new("cargo").args(&cmd_args).run()
        }
        RunMode::Prove => Process::new("cargo").args(&cmd_args).run(),
        RunMode::Verify => {
            // Generate the proof.
            Process::new("cargo").args(&cmd_args).run()?;

            // Verify the proof.
            let proof_filepath =
                proof_output_dirpath.join(format!("b{}.zkproof", block_string(end_block)));
            let verify_output_filepath = proof_output_dirpath.join("verify.out");
            let verify_runner = Process::new("cargo")
                .args(&[
                    "run",
                    "--release",
                    "--package=zero",
                    "--bin=verifier",
                    "--",
                    "-f",
                    proof_filepath.to_str().unwrap(),
                ])
                .pipe(&verify_output_filepath)?;
            verify_runner.run()
        }
    }
}

/// Converts a block ID to an appropriate string based on its variant.
fn block_string(block: BlockId) -> String {
    match block {
        BlockId::Number(number) => number.as_number().unwrap().to_string(),
        BlockId::Hash(hash) => hash.to_string(),
    }
}

/// Constructs the full command arguments for running the leader binary with
/// cargo.
fn command_args<'a>(mode: RunMode, leader_args: &'a [&str]) -> Vec<&'a str> {
    let mut args = Vec::from(&["run", "--release", "--package=zero", "--bin=leader", "--"]);
    match mode {
        RunMode::Prove | RunMode::Verify => args.push("--use-test-config"),
        RunMode::Test => args.push("--test-only"),
    }
    args.extend_from_slice(leader_args);
    args
}
