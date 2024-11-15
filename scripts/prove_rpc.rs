use std::{
    env::set_var,
    fmt::Display,
    fs::{create_dir_all, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use alloy::{eips::BlockId, transports::http::reqwest::Url};
use anyhow::{Context as _, Result};
use clap::{arg, Args, ValueEnum, ValueHint};

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

    // TODO: move this logic below when full match is done
    if let RunMode::Test = args.mode {
        set_var("ARITHMETIC_CIRCUIT_SIZE", "16..21");
        set_var("BYTE_PACKING_CIRCUIT_SIZE", "8..21");
        set_var("CPU_CIRCUIT_SIZE", "8..21");
        set_var("KECCAK_CIRCUIT_SIZE", "4..20");
        set_var("KECCAK_SPONGE_CIRCUIT_SIZE", "8..17");
        set_var("LOGIC_CIRCUIT_SIZE", "4..21");
        set_var("MEMORY_CIRCUIT_SIZE", "17..24");
        set_var("MEMORY_BEFORE_CIRCUIT_SIZE", "16..23");
        set_var("MEMORY_AFTER_CIRCUIT_SIZE", "7..23");
    }

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
    let log_out = File::create(&output_log_path).context("couldn't create log file")?;
    let log_err = log_out.try_clone().context("couldn't clone log file")?;

    /// Set file handle limit.
    const RECOMMENDED_FILE_LIMIT: isize = 8192;
    if !sysinfo::set_open_files_limit(RECOMMENDED_FILE_LIMIT) {
        eprintln!("WARNING: Unable to set file descriptor limit to recommended value: {RECOMMENDED_FILE_LIMIT}.");
    }

    let runner = Runner::new("cargo")
        .args(&[
            "run",
            "--release",
            "--package=zero",
            "--bin=leader",
            "--",
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
            &start_block.to_string(),
            "--checkpoint-block",
            &checkpoint_block.to_string(),
            "--end-block",
            &end_block.to_string(),
            "--backoff",
            &args.backoff.to_string(),
            "--max-retries",
            &args.max_retries.to_string(),
        ])
        .out(log_out)
        .err(log_err);
    match args.mode {
        RunMode::Test => runner.args(&["--use-test-config"]).run(),
        RunMode::Prove => todo!(),
        RunMode::Verify => todo!(),
    }
}

struct Runner {
    cmd: String,
    args: Vec<String>,
    out: Stdio,
    err: Stdio,
}

impl Runner {
    fn new(cmd: impl Into<String>) -> Self {
        Self {
            cmd: cmd.into(),
            args: vec![],
            out: Stdio::piped(),
            err: Stdio::piped(),
        }
    }

    fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    fn out(mut self, out: impl Into<Stdio>) -> Self {
        self.out = out.into();
        self
    }

    fn err(mut self, err: impl Into<Stdio>) -> Self {
        self.err = err.into();
        self
    }

    fn run(self) -> Result<()> {
        let output = Command::new(&self.cmd)
            .args(&self.args)
            .stdout(self.out)
            .stderr(self.err)
            .output()
            .context(format!("couldn't exec `{}`", &self.cmd))?;
        todo!()
    }
}
