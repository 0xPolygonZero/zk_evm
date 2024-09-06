pub mod cli;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::primitives::U256;
use anyhow::{Context, Result};
use futures::{future::BoxFuture, FutureExt, TryFutureExt, TryStreamExt};
use num_traits::ToPrimitive as _;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{oneshot, Semaphore};
use trace_decoder::{BlockTrace, OtherBlockData};
use tracing::{error, info};
use zero_bin_common::fs::generate_block_proof_file_name;

// All the proving tasks run in parallel. For the big block intervals,
// this leads to a common situation where the very distant future blocks are
// being proved first. So we create a pool of permits to limit the number of
// parallel proving block tasks, and they are retrieved in block increasing
// order. Initially we put 16, may be a reasonable default. We output proof file
// when the block batch is finished, so this helps with getting the results
// sooner.
const PARALLEL_BLOCK_PROVING_PERMIT_POOL_SIZE: usize = 16;
static PARALLEL_BLOCK_PROVING_PERMIT_POOL: Semaphore =
    Semaphore::const_new(PARALLEL_BLOCK_PROVING_PERMIT_POOL_SIZE);

#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub batch_size: usize,
    pub max_cpu_len_log: usize,
    pub save_inputs_on_error: bool,
    pub test_only: bool,
    pub proof_output_dir: PathBuf,
    pub keep_intermediate_proofs: bool,
    pub block_batch_size: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}

impl BlockProverInput {
    pub fn get_block_number(&self) -> U256 {
        self.other_data.b_data.b_meta.block_number.into()
    }

    pub async fn prove(
        self,
        runtime: Arc<Runtime>,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: Arc<ProverConfig>,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;
        use evm_arithmetization::SegmentDataIterator;
        use futures::{stream::FuturesUnordered, FutureExt};
        use paladin::directive::{Directive, IndexedStream};

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            ..
        } = *prover_config;

        let block_number = self.get_block_number();

        let use_burn_addr = cfg!(feature = "cdk_erigon");
        let block_generation_inputs = trace_decoder::entrypoint(
            self.block_trace,
            self.other_data,
            batch_size,
            use_burn_addr,
        )?;

        // Create segment proof.
        let seg_prove_ops = ops::SegmentProof {
            save_inputs_on_error,
        };

        // Aggregate multiple segment proofs to resulting segment proof.
        let seg_agg_ops = ops::SegmentAggProof {
            save_inputs_on_error,
        };

        // Aggregate batch proofs to a single proof.
        let batch_agg_ops = ops::BatchAggProof {
            save_inputs_on_error,
        };

        // Segment the batches, prove segments and aggregate them to resulting batch
        // proofs.
        let batch_proof_futs: FuturesUnordered<_> = block_generation_inputs
            .iter()
            .enumerate()
            .map(|(idx, txn_batch)| {
                let segment_data_iterator = SegmentDataIterator::<proof_gen::types::Field>::new(
                    txn_batch,
                    Some(max_cpu_len_log),
                );

                Directive::map(IndexedStream::from(segment_data_iterator), &seg_prove_ops)
                    .fold(&seg_agg_ops)
                    .run(&runtime)
                    .map(move |e| {
                        e.map(|p| (idx, proof_gen::proof_types::BatchAggregatableProof::from(p)))
                    })
            })
            .collect();

        // Fold the batch aggregated proof stream into a single proof.
        let final_batch_proof =
            Directive::fold(IndexedStream::new(batch_proof_futs), &batch_agg_ops)
                .run(&runtime)
                .await?;

        if let proof_gen::proof_types::BatchAggregatableProof::Agg(proof) = final_batch_proof {
            let block_number = block_number
                .to_u64()
                .context("block number overflows u64")?;
            let prev = match previous {
                Some(it) => Some(it.await?),
                None => None,
            };

            let block_proof = paladin::directive::Literal(proof)
                .map(&ops::BlockProof {
                    prev,
                    save_inputs_on_error,
                })
                .run(&runtime)
                .await?;

            info!("Successfully proved block {block_number}");

            Ok(block_proof.0)
        } else {
            anyhow::bail!("AggProof is is not GeneratedAggProof")
        }
    }

    pub async fn prove_test(
        self,
        runtime: Arc<Runtime>,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: Arc<ProverConfig>,
    ) -> Result<GeneratedBlockProof> {
        use std::iter::repeat;

        use futures::future;
        use paladin::directive::{Directive, IndexedStream};

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            ..
        } = *prover_config;

        let block_number = self.get_block_number();
        info!("Testing witness generation for block {block_number}.");

        let use_burn_addr = cfg!(feature = "cdk_erigon");
        let block_generation_inputs = trace_decoder::entrypoint(
            self.block_trace,
            self.other_data,
            batch_size,
            use_burn_addr,
        )?;

        let seg_ops = ops::SegmentProofTestOnly {
            save_inputs_on_error,
        };

        let simulation = Directive::map(
            IndexedStream::from(
                block_generation_inputs
                    .into_iter()
                    .zip(repeat(max_cpu_len_log)),
            ),
            &seg_ops,
        );

        simulation
            .run(&runtime)
            .await?
            .try_for_each(|_| future::ok(()))
            .await?;

        info!("Successfully generated witness for block {block_number}.");

        // Wait for previous block proof
        let _prev = match previous {
            Some(it) => Some(it.await?),
            None => None,
        };

        // Dummy proof to match expected output type.
        Ok(GeneratedBlockProof {
            b_height: block_number
                .to_u64()
                .expect("Block number should fit in a u64"),
            intern: proof_gen::proof_gen::dummy_proof()?,
        })
    }
}

async fn prove_block(
    block: BlockProverInput,
    runtime: Arc<Runtime>,
    previous_block_proof: Option<BoxFuture<'_, Result<GeneratedBlockProof>>>,
    prover_config: Arc<ProverConfig>,
) -> Result<GeneratedBlockProof> {
    if prover_config.test_only {
        block
            .prove_test(runtime, previous_block_proof, prover_config)
            .await
    } else {
        block
            .prove(runtime, previous_block_proof, prover_config)
            .await
    }
}

/// Prove all the blocks in the input, or simulate their execution depending on
/// the selected prover configuration. Return the list of block numbers that are
/// proved and if the proof data is not saved to disk, return the generated
/// block proofs as well.
pub async fn prove(
    mut block_receiver: Receiver<(BlockProverInput, bool)>,
    runtime: Arc<Runtime>,
    checkpoint_proof: Option<GeneratedBlockProof>,
    prover_config: Arc<ProverConfig>,
) -> Result<()> {
    use tokio::task::JoinSet;
    let mut block_counter: u64 = 0;
    let mut prev_proof: Option<BoxFuture<Result<GeneratedBlockProof>>> =
        checkpoint_proof.map(|proof| Box::pin(futures::future::ok(proof)) as BoxFuture<_>);

    let mut task_set: JoinSet<
        std::result::Result<std::result::Result<u64, anyhow::Error>, anyhow::Error>,
    > = JoinSet::new();
    while let Some((block_prover_input, is_last_block)) = block_receiver.recv().await {
        block_counter += 1;
        let (tx, rx) = oneshot::channel::<GeneratedBlockProof>();
        let prover_config = prover_config.clone();
        let previous_block_proof = prev_proof.take();
        let runtime = runtime.clone();
        let block_number = block_prover_input.get_block_number();

        let prove_permit = PARALLEL_BLOCK_PROVING_PERMIT_POOL.acquire().await?;

        let _abort_handle = task_set.spawn(async move {
            let block_number = block_prover_input.get_block_number();
            info!("Proving block {block_number}");
            // Prove the block
            let block_proof = prove_block(
                block_prover_input,
                runtime,
                previous_block_proof,
                prover_config.clone(),
            )
            .then(move |proof| async move {
                drop(prove_permit);
                let proof = proof.inspect_err(|e| {
                    error!("failed to generate proof for block {block_number}, error {e:?}")
                })?;
                let block_number = proof.b_height;

                // Write proof to disk if block is last in block batch,
                // or if the block is last in the interval (it contains all the necessary
                // information to verify the whole sequence). If flag
                // `keep_intermediate_proofs` is set, output all block proofs to disk.
                let is_block_batch_finished =
                    block_counter % prover_config.block_batch_size as u64 == 0;
                if !prover_config.test_only
                    && (is_last_block
                        || prover_config.keep_intermediate_proofs
                        || is_block_batch_finished)
                {
                    write_proof_to_dir(&prover_config.proof_output_dir, proof.clone())
                        .await
                        .inspect_err(|e| error!("failed to output proof for block {block_number} to directory {e:?}"))?;
                }

                if tx.send(proof).is_err() {
                    anyhow::bail!("Failed to send proof for block {block_number}");
                }

                Ok(block_number)
            })
            .await;

            Ok(block_proof)
        });
        prev_proof = Some(Box::pin(rx.map_err(move |e| {
            error!("failed to receive previous proof for block {block_number}: {e:?}");
            anyhow::Error::new(e)
        })));
        if is_last_block {
            break;
        }
    }

    while let Some(res) = task_set.join_next().await {
        let _proved_block_height = res???;
    }
    Ok(())
}

/// Write the proof to the `output_dir` directory.
async fn write_proof_to_dir(output_dir: &Path, proof: GeneratedBlockProof) -> Result<()> {
    // Check if output directory exists, and create one if it doesn't.
    if !output_dir.exists() {
        info!("Created output directory {:?}", output_dir.display());
        std::fs::create_dir(output_dir)?;
    }

    let block_proof_file_path =
        generate_block_proof_file_name(&output_dir.to_str(), proof.b_height);

    // Serialize as a single element array to match the expected format.
    let proof_serialized = serde_json::to_vec(&vec![proof])?;

    if let Some(parent) = block_proof_file_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut f = tokio::fs::File::create(block_proof_file_path.clone()).await?;
    f.write_all(&proof_serialized)
        .await
        .context("Failed to write proof to disk")?;

    info!(
        "Successfully wrote to disk proof file {}",
        block_proof_file_path.display()
    );
    Ok(())
}
