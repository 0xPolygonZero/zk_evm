use std::{fs::File, path::PathBuf, process::Command};

use anyhow::ensure;
use clap::{arg, Args, ValueEnum, ValueHint};

#[derive(ValueEnum, Copy, Clone)]
enum RunMode {
    /// Dummy proof is generated. Useful for quickly testing decoding and
    /// all other non-proving logic.
    Test,
    /// The proof is generated and verified.
    Verify,
}

#[derive(Args)]
pub struct ProveStdioArgs {
    /// Whether to generate a proof and verify it or not.
    mode: RunMode,
    /// JSON file containing the witness data.
    #[arg(value_hint = ValueHint::DirPath)]
    input_witness_file: PathBuf,
    /// The end of the block range to prove. If None, start_block-1 is used.
    #[arg(long, default_value_t = false)]
    use_test_config: bool,
    /// The batch size for block fetching.
    #[arg(long, default_value_t = 8)]
    block_batch_size: u32,
    /// The directory to output the proof files. If it does not exist, it will
    /// recursively be created.
    #[arg(short = 'o', long, value_hint = ValueHint::DirPath, default_value = "./proofs")]
    output_dir: PathBuf,
}

pub fn prove_via_stdio(args: ProveStdioArgs) -> anyhow::Result<()> {
    // Get number of cores of the system.
    let num_cpus = num_cpus::get().to_string();
    let mut envs = vec![
        ("RUST_MIN_STACK", "33554432"),
        ("RUST_BACKTRACE", "full"),
        ("RUST_LOG", "info"),
        ("RUSTFLAGS", "-C target-cpu=native -Zlinker-features=-lld"),
        ("RAYON_NUM_THREADS", num_cpus.as_str()),
        ("TOKIO_WORKER_THREADS", num_cpus.as_str()),
    ];

    match args.mode {
        RunMode::Test => {
            let mut cmd = prove_command(args, envs)?;
            let status = cmd.spawn()?.wait()?;
            ensure!(status.success(), "command failed with {}", status);
            Ok(())
        }
        RunMode::Verify => {
            // Build the targets before timing.
            let status = Command::new("cargo")
                .envs(envs.clone())
                .args(["build", "--release", "--jobs", num_cpus.as_str()])
                .spawn()?
                .wait()?;
            ensure!(status.success(), "command failed with {}", status);

            // Construct the command to run.
            add_verify_envs(&args, &mut envs)?;
            let mut cmd = prove_command(args, envs)?;

            // Time the proving.
            let start = std::time::Instant::now();
            let status = cmd.spawn()?.wait()?;
            ensure!(status.success(), "command failed with {}", status);
            let elapsed = start.elapsed();
            println!("Proving duration: {elapsed:?}");
            Ok(())
        }
    }
}

fn add_verify_envs(args: &ProveStdioArgs, envs: &mut Vec<(&str, &str)>) -> anyhow::Result<()> {
    let witness_filename = args
        .input_witness_file
        .to_str()
        .ok_or(anyhow::anyhow!("Invalid witness file path"))?;
    if witness_filename.contains("witness_b19807080") {
        envs.extend([
            ("ARITHMETIC_CIRCUIT_SIZE", "16..18"),
            ("BYTE_PACKING_CIRCUIT_SIZE", "8..15"),
            ("CPU_CIRCUIT_SIZE", "9..20"),
            ("KECCAK_CIRCUIT_SIZE", "7..18"),
            ("KECCAK_SPONGE_CIRCUIT_SIZE", "8..14"),
            ("LOGIC_CIRCUIT_SIZE", "5..17"),
            ("MEMORY_CIRCUIT_SIZE", "17..22"),
            ("MEMORY_BEFORE_CIRCUIT_SIZE", "16..20"),
            ("MEMORY_AFTER_CIRCUIT_SIZE", "7..20"),
            ("POSEIDON_CIRCUIT_SIZE", "4..8"),
        ]);
    } else if witness_filename.contains("witness_b3_b6") {
        envs.extend([
            ("ARITHMETIC_CIRCUIT_SIZE", "16..18"),
            ("BYTE_PACKING_CIRCUIT_SIZE", "8..15"),
            ("CPU_CIRCUIT_SIZE", "10..20"),
            ("KECCAK_CIRCUIT_SIZE", "4..13"),
            ("KECCAK_SPONGE_CIRCUIT_SIZE", "8..9"),
            ("LOGIC_CIRCUIT_SIZE", "4..14"),
            ("MEMORY_CIRCUIT_SIZE", "17..22"),
            ("MEMORY_BEFORE_CIRCUIT_SIZE", "16..18"),
            ("MEMORY_AFTER_CIRCUIT_SIZE", "7..8"),
            ("POSEIDON_CIRCUIT_SIZE", "4..8"),
        ]);
    } else {
        envs.extend([
            ("ARITHMETIC_CIRCUIT_SIZE", "16..18"),
            ("BYTE_PACKING_CIRCUIT_SIZE", "8..15"),
            ("CPU_CIRCUIT_SIZE", "9..20"),
            ("KECCAK_CIRCUIT_SIZE", "7..18"),
            ("KECCAK_SPONGE_CIRCUIT_SIZE", "8..14"),
            ("LOGIC_CIRCUIT_SIZE", "5..17"),
            ("MEMORY_CIRCUIT_SIZE", "17..22"),
            ("MEMORY_BEFORE_CIRCUIT_SIZE", "16..20"),
            ("MEMORY_AFTER_CIRCUIT_SIZE", "7..20"),
            // TODO(Robin): update Poseidon ranges here and below once Kernel ASM supports
            ("POSEIDON_CIRCUIT_SIZE", "4..8"),
        ]);
    }
    Ok(())
}

fn prove_command(args: ProveStdioArgs, envs: Vec<(&str, &str)>) -> anyhow::Result<Command> {
    let witness_file = File::open(&args.input_witness_file)?;
    let mut cmd = Command::new("cargo");
    cmd.envs(envs).stdin(witness_file);
    cmd.args([
        "run",
        "--release",
        "--package",
        "zero",
        "--bin",
        "leader",
        "--",
        "--runtime",
        "in-memory",
        "--load-strategy",
        "on-demand",
        "--block-batch-size",
        args.block_batch_size.to_string().as_str(),
        "--proof-output-dir",
        args.output_dir
            .to_str()
            .ok_or(anyhow::anyhow!("Invalid output dir path"))?,
    ]);
    if args.use_test_config {
        cmd.arg("--use-test-config");
    }
    cmd.arg("stdio");
    Ok(cmd)
}
