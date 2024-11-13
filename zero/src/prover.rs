zk_evm_common::check_chain_features!();

pub mod cli;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::primitives::U256;
use anyhow::{Context, Result};
use evm_arithmetization::Field;
use evm_arithmetization::SegmentDataIterator;
use futures::future::try_join_all;
use futures::{
    future, future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt, TryFutureExt,
    TryStreamExt,
};
use hashbrown::HashMap;
use num_traits::ToPrimitive as _;
use paladin::directive::{Directive, IndexedStream};
use paladin::runtime::Runtime;
use plonky2::gates::noop::NoopGate;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, oneshot, Semaphore};
use trace_decoder::observer::DummyObserver;
use trace_decoder::{BlockTrace, OtherBlockData, WireDisposition};
use tracing::{debug, error, info};

use crate::fs::generate_block_proof_file_name;
use crate::ops;
use crate::proof_types::GeneratedBlockProof;

/// `ProofRuntime` represents the runtime environments used for generating
/// different types of proofs. It contains separate runtimes for handling:
///
/// - `light_proof`: Typically for smaller, less resource-intensive tasks, such
///   as aggregation.
/// - `heavy_proof`: For larger, more computationally expensive tasks, such as
///   STARK proof generation.
pub struct ProofRuntime {
    pub light_proof: Runtime,
    pub heavy_proof: Runtime,
}

// All proving tasks are executed concurrently, which can cause issues for large
// block intervals, where distant future blocks may be proven first.
//
// We then create a pool to limit the number of parallel proving block
// tasks, retrieving new blocks in increasing order when some block proofs are
// complete.
//
// While proving a block interval, we will output proofs corresponding to block
// batches as soon as they are generated.
static PARALLEL_BLOCK_PROVING_PERMIT_POOL: Semaphore = Semaphore::const_new(0);

pub const WIRE_DISPOSITION: WireDisposition = {
    cfg_if::cfg_if! {
        if #[cfg(feature = "eth_mainnet")] {
            WireDisposition::Type1
        } else if #[cfg(feature = "cdk_erigon")] {
            WireDisposition::Type2
        } else {
            compile_error!("must select a feature");
        }
    }
};

#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub batch_size: usize,
    pub max_cpu_len_log: usize,
    pub save_inputs_on_error: bool,
    pub test_only: bool,
    pub proof_output_dir: PathBuf,
    pub keep_intermediate_proofs: bool,
    pub block_batch_size: usize,
    pub block_pool_size: usize,
    pub save_tries_on_error: bool,
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
        proof_runtime: Arc<ProofRuntime>,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: Arc<ProverConfig>,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            ..
        } = *prover_config;

        let block_number = self.get_block_number();

        let block_generation_inputs = trace_decoder::entrypoint(
            self.block_trace,
            self.other_data,
            batch_size,
            &mut DummyObserver::new(),
            WIRE_DISPOSITION,
        )?;

        let batch_count = block_generation_inputs.len();

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

        // Generate channels to communicate segments of each batch to a batch proving
        // task. We generate segments and send them to the proving task, where they
        // are proven in parallel.
        let (segment_senders, segment_receivers): (Vec<_>, Vec<_>) = (0..batch_count)
            .map(|_idx| {
                let (segment_tx, segment_rx) =
                    mpsc::channel::<Option<evm_arithmetization::AllData>>(1);
                (segment_tx, segment_rx)
            })
            .unzip();

        // The size of this channel does not matter much, as it is only used to collect
        // batch proofs.
        let (batch_proof_tx, mut batch_proof_rx) =
            mpsc::channel::<(usize, crate::proof_types::BatchAggregatableProof)>(32);

        // Spin up a task for each batch to generate segments for that batch
        // and send them to the proving task.
        let segment_generation_task = tokio::spawn(async move {
            let mut batch_segment_futures: FuturesUnordered<_> = FuturesUnordered::new();

            for (batch_idx, (txn_batch, segment_tx)) in block_generation_inputs
                .into_iter()
                .zip(segment_senders)
                .enumerate()
            {
                batch_segment_futures.push(async move {
                    let segment_data_iterator =
                        SegmentDataIterator::<Field>::new(&txn_batch, Some(max_cpu_len_log));
                    for (segment_idx, segment_data) in segment_data_iterator.enumerate() {
                        segment_tx
                            .send(Some(segment_data))
                            .await
                            .context(format!("failed to send segment data for batch {batch_idx} segment {segment_idx}"))?;
                    }
                    // Mark the end of the batch segments by sending `None`
                    segment_tx
                        .send(None)
                        .await
                        .context(format!("failed to send end segment data indicator for batch {batch_idx}"))?;
                    Ok::<(), anyhow::Error>(())
                });
            }
            while let Some(it) = batch_segment_futures.next().await {
                // In case of an error, propagate the error to the main task
                it?;
            }
            Ok::<(), anyhow::Error>(())
        });

        let proof_runtime_ = proof_runtime.clone();
        let batches_proving_task = tokio::spawn(async move {
            let mut batch_proving_futures: FuturesUnordered<_> = FuturesUnordered::new();
            // Span a proving subtask for each batch where we generate segment proofs
            // and aggregate them to batch proof.
            for (batch_idx, mut segment_rx) in segment_receivers.into_iter().enumerate() {
                let batch_proof_tx = batch_proof_tx.clone();
                let seg_prove_ops = seg_prove_ops.clone();
                let seg_agg_ops = seg_agg_ops.clone();
                let proof_runtime = proof_runtime_.clone();
                // Tasks to dispatch proving jobs and aggregate segment proofs of one batch
                batch_proving_futures.push(async move {
                    let mut batch_segment_aggregatable_proofs = Vec::new();

                    // This channel collects segment proofs from the one batch
                    // proven in parallel. The size of this channel does not matter much,
                    // as it is only used to collect segment aggregatable proofs.
                    let (segment_proof_tx, mut segment_proof_rx) =
                        mpsc::channel::<(usize, crate::proof_types::SegmentAggregatableProof)>(32);

                    // Wait for segments and dispatch them to the segment proof worker task.
                    // The segment proof worker task will prove the segment and send it back.
                    let mut segment_counter = 0;
                    let mut segment_proving_tasks = Vec::new();
                    while let Some(segment_data) = segment_rx.recv().await {
                        if segment_data.is_none() {
                            break;
                        }
                        let seg_prove_ops = seg_prove_ops.clone();
                        let proof_runtime = proof_runtime.clone();
                        let segment_proof_tx = segment_proof_tx.clone();
                        // Prove one segment in a dedicated async task.
                        let segment_proving_task = tokio::spawn(async move {
                            if let Some(segment_data) = segment_data {
                                debug!("proving the batch {batch_idx} segment nr. {segment_counter}");
                                let seg_aggregatable_proof= Directive::map(
                                    IndexedStream::from([segment_data]),
                                    &seg_prove_ops,
                                )
                                    .run(&proof_runtime.heavy_proof)
                                    .await?
                                    .into_values_sorted()
                                    .await?
                                    .into_iter()
                                    .next()
                                    .context(format!(
                                        "failed to get segment proof, batch: {batch_idx}, segment: {segment_counter}"
                                    ))?;

                                segment_proof_tx
                                    .send((segment_counter, seg_aggregatable_proof))
                                    .await
                                    .context(format!(
                                        "unable to send segment proof, batch: {batch_idx}, segment: {segment_counter}"
                                    ))?;
                            };
                            Ok::<(), anyhow::Error>(())
                        });

                        segment_proving_tasks.push(segment_proving_task);
                        segment_counter += 1;
                    }
                    drop(segment_proof_tx);
                    // Wait for all the segment proving tasks of one batch to finish.
                    while let Some((segment_idx, segment_aggregatable_proof)) = segment_proof_rx.recv().await {
                        batch_segment_aggregatable_proofs.push((segment_idx, segment_aggregatable_proof));
                    }
                    try_join_all(segment_proving_tasks).await?;
                    batch_segment_aggregatable_proofs.sort_by(|(a, _), (b, _)| a.cmp(b));
                    debug!(block_number=%block_number, batch=%batch_idx, "finished proving all segments");
                    // We have proved all the segments in a batch,
                    // now we need to aggregate them to the batch proof.
                    // Fold the segment aggregated proof stream into a single batch proof.
                    let batch_proof = if batch_segment_aggregatable_proofs.len() == 1 {
                        // If there is only one segment aggregated proof, just transform it to batch proof.
                        (batch_idx, crate::proof_types::BatchAggregatableProof::from(
                            batch_segment_aggregatable_proofs.pop().map(|(_, it)| it).unwrap(),
                        ))
                    } else {
                        Directive::fold(IndexedStream::from(batch_segment_aggregatable_proofs.into_iter().map(|(_, it)| it)), &seg_agg_ops)
                            .run(&proof_runtime.light_proof)
                            .map(move |e| {
                                e.map(|p| {
                                    (
                                        batch_idx,
                                        crate::proof_types::BatchAggregatableProof::from(p),
                                    )
                                })
                            })
                            .await?
                    };
                    debug!(block_number=%block_number, batch=%batch_idx, "generated batch proof for block");
                    batch_proof_tx.send(batch_proof).await.context(format!(
                        "unable to send batch proof, block: {block_number}, batch: {batch_idx}"
                    ))?;
                    Ok::<(), anyhow::Error>(())
                });
            }
            // Wait for all the batch proving tasks to finish. Exit early on error.
            while let Some(it) = batch_proving_futures.next().await {
                it?;
            }
            Ok::<(), anyhow::Error>(())
        });

        // Collect all the batch proofs.
        let mut batch_proofs: Vec<(usize, crate::proof_types::BatchAggregatableProof)> = Vec::new();
        while let Some((batch_idx, batch_proof)) = batch_proof_rx.recv().await {
            batch_proofs.push((batch_idx, batch_proof));
        }
        debug!(block_number=%block_number, "collected all batch proofs");

        // Wait for the segment generation and proving tasks to finish.
        try_join_all([segment_generation_task, batches_proving_task]).await?;

        batch_proofs.sort_by(|(a, _), (b, _)| a.cmp(b));

        // Fold the batch aggregated proof stream into a single proof.
        let final_batch_proof = Directive::fold(
            IndexedStream::from(batch_proofs.into_iter().map(|(_, it)| it)),
            &batch_agg_ops,
        )
        .run(&proof_runtime.light_proof)
        .await?;

        if let crate::proof_types::BatchAggregatableProof::BatchAgg(proof) = final_batch_proof {
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
                .run(&proof_runtime.light_proof)
                .await?;

            info!("Successfully proved block {block_number}");

            Ok(block_proof.0)
        } else {
            anyhow::bail!("AggProof is is not GeneratedAggProof")
        }
    }

    pub async fn prove_test(
        self,
        proof_runtime: Arc<ProofRuntime>,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: Arc<ProverConfig>,
    ) -> Result<GeneratedBlockProof> {
        use std::iter::repeat;

        use paladin::directive::{Directive, IndexedStream};

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            save_tries_on_error,
            ..
        } = *prover_config;

        let block_number = self.get_block_number();
        info!("Testing witness generation for block {block_number}.");

        let block_generation_inputs = trace_decoder::entrypoint(
            self.block_trace,
            self.other_data,
            batch_size,
            &mut DummyObserver::new(),
            WIRE_DISPOSITION,
        )?;

        let seg_ops = ops::SegmentProofTestOnly {
            save_inputs_on_error,
            save_tries_on_error,
        };

        let simulation = Directive::map(
            IndexedStream::from(
                block_generation_inputs
                    .into_iter()
                    .enumerate()
                    .zip(repeat(max_cpu_len_log))
                    .map(|((batch_index, txn_batch), max_cpu_len_log)| {
                        (txn_batch, max_cpu_len_log, batch_index)
                    }),
            ),
            &seg_ops,
        );

        simulation
            .run(&proof_runtime.light_proof)
            .await?
            .try_for_each(|_| future::ok(()))
            .await?;

        info!("Successfully generated witness for block {block_number}.");

        // Wait for previous block proof
        let _prev = match previous {
            Some(it) => Some(it.await?),
            None => None,
        };

        // Build a dummy proof for output type consistency
        let dummy_proof = {
            let mut builder = CircuitBuilder::new(CircuitConfig::default());
            builder.add_gate(NoopGate, vec![]);
            let circuit_data = builder.build::<_>();

            plonky2::recursion::dummy_circuit::dummy_proof(&circuit_data, HashMap::default())?
        };

        // Dummy proof to match expected output type.
        Ok(GeneratedBlockProof {
            b_height: block_number
                .to_u64()
                .expect("Block number should fit in a u64"),
            intern: dummy_proof,
        })
    }
}

async fn prove_block(
    block: BlockProverInput,
    proof_runtime: Arc<ProofRuntime>,
    previous_block_proof: Option<BoxFuture<'_, Result<GeneratedBlockProof>>>,
    prover_config: Arc<ProverConfig>,
) -> Result<GeneratedBlockProof> {
    if prover_config.test_only {
        block
            .prove_test(proof_runtime, previous_block_proof, prover_config)
            .await
    } else {
        block
            .prove(proof_runtime, previous_block_proof, prover_config)
            .await
    }
}

/// Prove all the blocks in the input, or simulate their execution depending on
/// the selected prover configuration. Return the list of block numbers that are
/// proved and if the proof data is not saved to disk, return the generated
/// block proofs as well.
pub async fn prove(
    mut block_receiver: Receiver<(BlockProverInput, bool)>,
    proof_runtime: Arc<ProofRuntime>,
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

    PARALLEL_BLOCK_PROVING_PERMIT_POOL.add_permits(prover_config.block_pool_size);

    while let Some((block_prover_input, is_last_block)) = block_receiver.recv().await {
        block_counter += 1;
        let (tx, rx) = oneshot::channel::<GeneratedBlockProof>();
        let prover_config = prover_config.clone();
        let previous_block_proof = prev_proof.take();
        let proof_runtime = proof_runtime.clone();
        let block_number = block_prover_input.get_block_number();

        let prove_permit = PARALLEL_BLOCK_PROVING_PERMIT_POOL.acquire().await?;

        let _abort_handle = task_set.spawn(async move {
            let block_number = block_prover_input.get_block_number();
            info!("Proving block {block_number}");
            // Prove the block
            let block_proof = prove_block(
                block_prover_input,
                proof_runtime,
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
