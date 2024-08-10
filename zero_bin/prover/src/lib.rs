pub mod cli;

use std::future::Future;
use std::path::PathBuf;

use alloy::primitives::{BlockNumber, U256};
use anyhow::{Context, Result};
use futures::stream::FuturesOrdered;
use futures::{future::BoxFuture, FutureExt, TryFutureExt, TryStreamExt};
use num_traits::ToPrimitive as _;
use paladin::runtime::Runtime;
use proof_gen::proof_types::GeneratedBlockProof;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use trace_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};
use tracing::info;
use zero_bin_common::fs::generate_block_proof_file_name;

#[derive(Debug, Clone, Copy)]
pub struct ProverConfig {
    pub batch_size: usize,
    pub segment_chunk_size: usize,
    pub max_cpu_len_log: usize,
    pub save_inputs_on_error: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}
fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

impl BlockProverInput {
    pub fn get_block_number(&self) -> U256 {
        self.other_data.b_data.b_meta.block_number.into()
    }

    #[cfg(not(feature = "test_only"))]
    pub async fn prove(
        self,
        runtime: &Runtime,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: ProverConfig,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;
        use evm_arithmetization::prover::{SegmentDataChunkIterator, SegmentDataIterator};
        use paladin::directive::{Directive, IndexedStream};
        use proof_gen::types::Field;

        let ProverConfig {
            max_cpu_len_log,
            batch_size,
            segment_chunk_size,
            save_inputs_on_error,
        } = prover_config;

        let block_number = self.get_block_number();
        let other_data = self.other_data;
        let block_generation_inputs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
            batch_size,
        )?;
        info!(
            "Proving block {}, generation inputs count: {}, batch size: {}, segment chunk size: {}",
            block_number,
            block_generation_inputs.len(),
            batch_size,
            segment_chunk_size
        );

        // Create segment proof
        let seg_prove_ops = ops::SegmentProof {
            save_inputs_on_error,
        };

        // Generate segment data.
        let seg_agg_ops = ops::SegmentAggProof {
            save_inputs_on_error,
        };

        // Aggregate batch proofs to a single proof
        let batch_agg_ops = ops::BatchAggProof {
            save_inputs_on_error,
        };

        let mut all_block_batch_proofs = Vec::new();
        // Loop for all generation inputs in the block
        for generation_inputs in block_generation_inputs {
            let mut segment_data_iter =
                SegmentDataIterator::<Field>::new(&generation_inputs, Some(max_cpu_len_log));
            let mut chunk_segment_iter =
                SegmentDataChunkIterator::new(&mut segment_data_iter, segment_chunk_size);

            let mut chunk_seg_aggregatable_proofs = Vec::new();
            // We take one chunk of segments, perform proving and
            // aggregate it into a single chunk proof
            while let Some(chunk) = chunk_segment_iter.next() {
                chunk_seg_aggregatable_proofs.push(
                    Directive::map(IndexedStream::from(chunk.into_iter()), &seg_prove_ops)
                        .fold(&seg_agg_ops)
                        .run(runtime)
                        .await,
                );
            }

            // Fold all the generation input segment chunk proofs
            // into a single batch proof
            let batch_aggregated_proof = Directive::fold(
                IndexedStream::from(chunk_seg_aggregatable_proofs.into_iter().collect::<Result<
                    Vec<_>,
                    anyhow::Error,
                >>(
                )?),
                &seg_agg_ops,
            )
            .run(runtime)
            .map(move |e| e.map(proof_gen::proof_types::BatchAggregatableProof::from))
            .await?;
            all_block_batch_proofs.push(batch_aggregated_proof);
        }
        // Fold all the aggregated batch proofs into a single batch proof
        let final_txn_proof = Directive::fold(
            IndexedStream::from(all_block_batch_proofs.into_iter()),
            &batch_agg_ops,
        )
        .run(runtime)
        .await?;

        if let proof_gen::proof_types::BatchAggregatableProof::Agg(proof) = final_txn_proof {
            let block_number = block_number
                .to_u64()
                .context("block number overflows u64")?;
            let prev = match previous {
                Some(it) => Some(it.await?),
                None => None,
            };

            // Generate the block proof
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

    #[cfg(feature = "test_only")]
    pub async fn prove(
        self,
        _runtime: &Runtime,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        prover_config: ProverConfig,
    ) -> Result<GeneratedBlockProof> {
        use evm_arithmetization::prover::testing::simulate_execution_all_segments;
        use plonky2::field::goldilocks_field::GoldilocksField;

        let block_number = self.get_block_number();
        info!("Testing witness generation for block {block_number}.");

        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
            prover_config.batch_size,
        )?;

        type F = GoldilocksField;
        for txn in txs.into_iter() {
            simulate_execution_all_segments::<F>(txn, prover_config.max_cpu_len_log)?;
        }

        // Wait for previous block proof
        let _prev = match previous {
            Some(it) => Some(it.await?),
            None => None,
        };

        info!("Successfully generated witness for block {block_number}.");

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
                let fut = block
                    .prove(runtime, prev.take(), prover_config)
                    .then(move |proof| async move {
                        let proof = proof?;
                        let block_number = proof.b_height;

                        // Write latest generated proof to disk if proof_output_dir is provided
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
                    .boxed();

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
