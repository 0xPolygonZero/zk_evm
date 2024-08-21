pub mod cli;

use std::future::Future;
use std::path::PathBuf;

use alloy::primitives::{BlockNumber, U256};
use anyhow::{Context, Result};
use futures::{future::BoxFuture, stream::FuturesOrdered, FutureExt, TryFutureExt, TryStreamExt};
use num_traits::ToPrimitive as _;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use trace_decoder::{BlockTrace, OtherBlockData};
use tracing::info;
use zero_bin_common::fs::generate_block_proof_file_name;

#[derive(Debug, Clone, Copy)]
pub struct ProverConfig {
    pub batch_size: usize,
    pub max_cpu_len_log: usize,
    pub save_inputs_on_error: bool,
    pub test_only: bool,
}

#[derive(Debug, Deserialize, Serialize)]
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
        runtime: &Runtime,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: ProverConfig,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;
        use evm_arithmetization::prover::SegmentDataIterator;
        use futures::{stream::FuturesUnordered, FutureExt};
        use paladin::directive::{Directive, IndexedStream};

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            test_only: _,
        } = prover_config;

        let block_number = self.get_block_number();

        let block_generation_inputs =
            trace_decoder::entrypoint(self.block_trace, self.other_data, batch_size)?;

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
                    .run(runtime)
                    .map(move |e| {
                        e.map(|p| (idx, proof_gen::proof_types::BatchAggregatableProof::from(p)))
                    })
            })
            .collect();

        // Fold the batch aggregated proof stream into a single proof.
        let final_batch_proof =
            Directive::fold(IndexedStream::new(batch_proof_futs), &batch_agg_ops)
                .run(runtime)
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
                .run(runtime)
                .await?;

            info!("Successfully proved block {block_number}");

            Ok(block_proof.0)
        } else {
            anyhow::bail!("AggProof is is not GeneratedAggProof")
        }
    }

    pub async fn prove_test(
        self,
        runtime: &Runtime,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: ProverConfig,
    ) -> Result<GeneratedBlockProof> {
        use std::iter::repeat;

        use futures::future;
        use paladin::directive::{Directive, IndexedStream};

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            save_inputs_on_error,
            test_only: _,
        } = prover_config;

        let block_number = self.get_block_number();
        info!("Testing witness generation for block {block_number}.");

        let block_generation_inputs =
            trace_decoder::entrypoint(self.block_trace, self.other_data, batch_size)?;

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
            .run(runtime)
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

#[derive(Debug, Deserialize, Serialize)]
pub struct ProverInput {
    pub blocks: Vec<BlockProverInput>,
}

impl ProverInput {
    /// Prove all the blocks in the input.
    /// Return the list of block numbers that are proved and if the proof data
    /// is not saved to disk, return the generated block proofs as well.
    pub async fn prove(
        self,
        runtime: &Runtime,
        previous_proof: Option<GeneratedBlockProof>,
        prover_config: ProverConfig,
        proof_output_dir: Option<PathBuf>,
    ) -> Result<Vec<(BlockNumber, Option<GeneratedBlockProof>)>> {
        let mut prev: Option<BoxFuture<Result<GeneratedBlockProof>>> =
            previous_proof.map(|proof| Box::pin(futures::future::ok(proof)) as BoxFuture<_>);

        let results: FuturesOrdered<_> = self
            .blocks
            .into_iter()
            .map(|block| {
                let (tx, rx) = oneshot::channel::<GeneratedBlockProof>();

                // Prove the block
                let proof_output_dir = proof_output_dir.clone();
                let fut = if prover_config.test_only {
                    block
                        .prove_test(runtime, prev.take(), prover_config)
                        .then(move |proof| async move {
                            let proof = proof?;
                            let block_number = proof.b_height;

                            // We ignore the returned dummy proof in test-only mode.
                            Ok((block_number, None))
                        })
                        .boxed()
                } else {
                    block
                        .prove(runtime, prev.take(), prover_config)
                        .then(move |proof| async move {
                            let proof = proof?;
                            let block_number = proof.b_height;

                            // Write latest generated proof to disk if proof_output_dir is provided.
                            let return_proof: Option<GeneratedBlockProof> =
                                if proof_output_dir.is_some() {
                                    ProverInput::write_proof(proof_output_dir, &proof).await?;
                                    None
                                } else {
                                    Some(proof.clone())
                                };

                            if tx.send(proof).is_err() {
                                anyhow::bail!("Failed to send proof");
                            }

                            Ok((block_number, return_proof))
                        })
                        .boxed()
                };

                prev = Some(Box::pin(rx.map_err(anyhow::Error::new)));

                fut
            })
            .collect();

        results.try_collect().await
    }

    /// Write the proof to the disk (if `output_dir` is provided) or stdout.
    pub(crate) async fn write_proof(
        output_dir: Option<PathBuf>,
        proof: &GeneratedBlockProof,
    ) -> Result<()> {
        let proof_serialized = serde_json::to_vec(proof)?;
        let block_proof_file_path =
            output_dir.map(|path| generate_block_proof_file_name(&path.to_str(), proof.b_height));
        match block_proof_file_path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                let mut f = tokio::fs::File::create(p).await?;
                f.write_all(&proof_serialized)
                    .await
                    .context("Failed to write proof to disk")
            }
            None => tokio::io::stdout()
                .write_all(&proof_serialized)
                .await
                .context("Failed to write proof to stdout"),
        }
    }
}
