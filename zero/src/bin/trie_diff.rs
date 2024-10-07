//! This binary is a debugging tool used to compare
//! the trace decoder output tries and the post kernel execution tries (state,
//! transaction and receipt). As input, it uses a standard witness JSON file
//! (same as `leader` in stdio mode), and it runs block by block the trace
//! decoder and `test_only` mode of the prover. On the first error that happens
//! trace decoder and prover tries are compared, and the details of the trie
//! differences are printed.
//!
//! Example usage:
//! ```
//! RUST_LOG=info cargo run --bin trie_diff -- --batch-size 2 < ./artifacts/witness_b19807080.json
//! ```

use std::io::Read;
use std::iter::repeat;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueHint};
use evm_arithmetization::generation::DebugOutputTries;
use futures::{future, TryStreamExt};
use paladin::directive::{Directive, IndexedStream};
use paladin::runtime::Runtime;
use regex::Regex;
use trace_decoder::observer::TriesObserver;
use tracing::{error, info};
use zero::ops::register;
use zero::prover::{cli::CliProverConfig, BlockProverInput, ProverConfig};

/// This binary is a debugging tool used to compare
/// the trace decoder output tries and the post kernel execution tries (state,
/// transaction and receipt).
///
/// Usage:
///
/// `trie_diff <OPTIONS> < ./witness_json_input.json`
#[derive(Parser)]
#[command(version = zero::version(), propagate_version = true)]
pub(crate) struct Cli {
    /// Prover configuration
    #[clap(flatten)]
    pub(crate) prover_config: CliProverConfig,

    /// The previous proof output.
    #[arg(long, short = 'f', value_hint = ValueHint::FilePath)]
    previous_proof: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    zero::tracing::init();

    let args = Cli::parse();

    // Load witness input from stdin
    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    // Debug run, we always use in-memory execution
    let paladin_config = paladin::config::Config {
        amqp_uri: None,
        runtime: paladin::config::Runtime::InMemory,
        ..Default::default()
    };
    let runtime = Arc::new(Runtime::from_config(&paladin_config, register()).await?);

    // Tries are computed in the kernel so no need to run proving, test_only mode is
    // enough. We hardcode prover arguments that we need for trie diff computation.
    let prover_config: Arc<ProverConfig> = Arc::new(ProverConfig {
        test_only: true,
        save_inputs_on_error: true,
        save_tries_on_error: true,
        ..args.prover_config.into()
    });

    let seg_ops = zero::ops::SegmentProofTestOnly {
        save_inputs_on_error: prover_config.save_inputs_on_error,
        save_tries_on_error: prover_config.save_tries_on_error,
    };

    let des = &mut serde_json::Deserializer::from_str(&buffer);
    let block_prover_inputs = serde_path_to_error::deserialize::<_, Vec<BlockProverInput>>(des)?
        .into_iter()
        .collect::<Vec<_>>();

    for block_prover_input in block_prover_inputs {
        let mut observer = TriesObserver::new();
        let block_number = block_prover_input
            .other_data
            .b_data
            .b_meta
            .block_number
            .low_u64();
        let block_generation_inputs = trace_decoder::entrypoint(
            block_prover_input.block_trace.clone(),
            block_prover_input.other_data.clone(),
            prover_config.batch_size,
            &mut observer,
        )?;
        info!(
            "Number of collected batch tries for block {}: {}",
            block_number,
            observer.data.len()
        );

        info!("Running trie diff simulation for block {block_number} ...");
        let simulation = Directive::map(
            IndexedStream::from(
                block_generation_inputs
                    .clone()
                    .into_iter()
                    .enumerate()
                    .zip(repeat(prover_config.max_cpu_len_log))
                    .map(|((batch_index, inputs), max_cpu_len_log)| {
                        (inputs, max_cpu_len_log, batch_index)
                    }),
            ),
            &seg_ops,
        );

        if let Err(e2) = simulation
            .run(&runtime)
            .await
            .inspect_err(|e1| {
                error!("Failed to run simulation for block {block_number}, error: {e1}")
            })?
            .try_for_each(|_| future::ok(()))
            .await
        {
            // Try to parse block and batch index from error message.
            let error_message = e2.to_string();
            let re = Regex::new(r"block:(\d+) batch:(\d+)")?;
            if let Some(cap) = re.captures(&error_message) {
                let block_number: u64 = cap[1].parse()?;
                let batch_index: usize = cap[2].parse()?;

                let prover_tries =
                    zero::debug_utils::load_tries_from_disk(block_number, batch_index)?;

                info!("Performing trie comparison for block {block_number} batch {batch_index}...");
                zero::trie_diff::compare_tries(
                    &block_prover_input,
                    batch_index,
                    &DebugOutputTries {
                        state_trie: observer.data[prover_tries.batch_index]
                            .tries
                            .state
                            .as_hashed_partial_trie()
                            .clone(),
                        transaction_trie: observer.data[prover_tries.batch_index]
                            .tries
                            .transaction
                            .clone()
                            .into(),
                        receipt_trie: observer.data[prover_tries.batch_index]
                            .tries
                            .receipt
                            .clone()
                            .into(),
                    },
                    &prover_tries.tries,
                )?;

                info!("Trie comparison finished for block {block_number} batch {batch_index}");
                return Ok(());
            } else {
                error!(
                    "Failed to extract block and batch numbers from error message, could not run tries comparison: {}",
                    error_message
                );
                return Err(e2);
            }
        }

        info!("Trie diff for block {block_number} finished, no problems found.")
    }

    Ok(())
}
