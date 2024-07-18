use std::path::PathBuf;
use std::time::Instant;
use std::{future::Future, time::Duration};

use alloy::primitives::{BlockNumber, U256};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use futures::{future::BoxFuture, stream::FuturesOrdered, FutureExt, TryFutureExt, TryStreamExt};
use num_traits::ToPrimitive as _;
use ops::TxProof;
use paladin::{
    directive::{Directive, IndexedStream},
    runtime::Runtime,
};
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

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}
fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

#[derive(Debug, Clone)]
pub struct BenchmarkedGeneratedBlockProof {
    pub proof: GeneratedBlockProof,
    pub prep_dur: Option<Duration>,
    pub proof_dur: Option<Duration>,
    pub agg_wait_dur: Option<Duration>,
    pub agg_dur: Option<Duration>,
    pub total_dur: Option<Duration>,
    pub n_txs: u64,
    pub gas_used: u64,
    pub gas_used_per_tx: Vec<u64>,
    pub difficulty: u64,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

unsafe impl Send for BenchmarkedGeneratedBlockProof {}

impl From<BenchmarkedGeneratedBlockProof> for GeneratedBlockProof {
    fn from(value: BenchmarkedGeneratedBlockProof) -> Self {
        value.proof
    }
}

impl BlockProverInput {
    pub fn get_block_number(&self) -> U256 {
        self.other_data.b_data.b_meta.block_number.into()
    }

    #[cfg(not(feature = "test_only"))]
    pub async fn prove_and_benchmark(
        self,
        runtime: &Runtime,
        previous: Option<impl Future<Output = Result<BenchmarkedGeneratedBlockProof>>>,
        save_inputs_on_error: bool,
    ) -> Result<BenchmarkedGeneratedBlockProof> {
        // Start timing for preparation
        let prep_start = Instant::now();
        let start_time: DateTime<Utc> = Utc::now();

        // Basic preparation
        use anyhow::Context as _;
        let block_number = self.get_block_number();
        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
        )?;

        let n_txs = txs.len();
        let gas_used = u64::try_from(other_data.b_data.b_meta.block_gas_used).expect("Overflow");
        let gas_used_per_tx = txs
            .iter()
            .map(|tx| {
                u64::try_from(tx.gas_used_after - tx.gas_used_before).expect("Overflow of gas")
            })
            .collect();
        let difficulty = other_data.b_data.b_meta.block_difficulty;

        // Get time took to prepare
        let prep_dur = prep_start.elapsed();

        info!(
            "Completed pre-proof work for block {} in {} secs",
            block_number,
            prep_dur.as_secs_f64()
        );

        let proof_start = Instant::now();
        let agg_proof = IndexedStream::from(txs)
            .map(&TxProof {
                save_inputs_on_error,
            })
            .fold(&ops::AggProof {
                save_inputs_on_error,
            })
            .run(runtime)
            .await?;
        let proof_dur = proof_start.elapsed();

        info!(
            "Completed tx proofs for block {} in {} secs",
            block_number,
            proof_dur.as_secs_f64()
        );

        if let proof_gen::proof_types::AggregatableProof::Agg(proof) = agg_proof {
            let agg_wait_start = Instant::now();
            let block_number = block_number
            .to_u64()
            .context("block number overflows u64")?;
            let prev = match previous {
                Some(it) => Some(it.await?),
                None => None,
            };
            let agg_wait_dur = agg_wait_start.elapsed();
        
            let agg_start = Instant::now();
            let block_proof = paladin::directive::Literal(proof)
                .map(&ops::BlockProof {
                    prev: prev.map(|p| p.proof),
                    save_inputs_on_error,
                })
                .run(runtime)
                .await?;
            let agg_dur = agg_start.elapsed();
            info!(
                "Completed tx proof agg for block {} in {} secs",
                block_number,
                agg_dur.as_secs_f64()
            );
            let end_time: DateTime<Utc> = Utc::now();
            let total_dur: Duration = prep_start.elapsed();
            info!(
                "Successfully proved block {block_number} (in {} secs)",
                total_dur.as_secs_f64()
            );
            // Return the block proof
            Ok(BenchmarkedGeneratedBlockProof {
                proof: block_proof.0,
                total_dur: Some(prep_start.elapsed()),
                proof_dur: Some(proof_dur),
                prep_dur: Some(prep_dur),
                agg_wait_dur: Some(agg_wait_dur),
                agg_dur: Some(agg_dur),
                n_txs: n_txs as u64,
                gas_used,
                gas_used_per_tx,
                difficulty: u64::try_from(difficulty).expect("Difficulty overflow"),
                start_time,
                end_time,
            })
        } else {
            anyhow::bail!("AggProof is is not GeneratedAggProof")
        }
    }

    #[cfg(not(feature = "test_only"))]
    pub async fn prove(
        self,
        runtime: &Runtime,
        previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        save_inputs_on_error: bool,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;

        let block_number = self.get_block_number();

        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
        )?;

        let agg_proof = IndexedStream::from(txs)
            .map(&TxProof {
                save_inputs_on_error,
            })
            .fold(&ops::AggProof {
                save_inputs_on_error,
            })
            .run(runtime)
            .await?;

        if let proof_gen::proof_types::AggregatableProof::Agg(proof) = agg_proof {
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

    #[cfg(feature = "test_only")]
    pub async fn prove(
        self,
        runtime: &Runtime,
        _previous: Option<impl Future<Output = Result<GeneratedBlockProof>>>,
        save_inputs_on_error: bool,
    ) -> Result<GeneratedBlockProof> {
        let block_number = self.get_block_number();
        info!("Testing witness generation for block {block_number}.");

        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
        )?;

        IndexedStream::from(txs)
            .map(&TxProof {
                save_inputs_on_error,
            })
            .run(runtime)
            .await?
            .try_collect::<Vec<_>>()
            .await?;

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
        save_inputs_on_error: bool,
        proof_output_dir: Option<PathBuf>,
    ) -> Result<Vec<(BlockNumber, Option<GeneratedBlockProof>)>> {
        let mut prev: Option<BoxFuture<Result<GeneratedBlockProof>>> =
            previous_proof.map(|proof| Box::pin(futures::future::ok(proof)) as BoxFuture<_>);

        let results: FuturesOrdered<_> = self
            .blocks
            .into_iter()
            .map(|block| {
                let block_number = block.get_block_number();
                info!("Proving block {block_number}");

                let (tx, rx) = oneshot::channel::<GeneratedBlockProof>();

                // Prove the block
                let proof_output_dir = proof_output_dir.clone();
                let fut = block
                    .prove(runtime, prev.take(), save_inputs_on_error)
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

    /// Prove all the blocks in the input.
    /// Return the list of block numbers that are proved and if the proof data
    /// is not saved to disk, return the generated block proofs as well.
    pub async fn prove_and_benchmark(
        self,
        runtime: &Runtime,
        previous_proof: Option<BenchmarkedGeneratedBlockProof>,
        save_inputs_on_error: bool,
        proof_output_dir: Option<PathBuf>,
    ) -> Result<Vec<(BlockNumber, Option<BenchmarkedGeneratedBlockProof>)>> {
        let mut prev: Option<BoxFuture<Result<BenchmarkedGeneratedBlockProof>>> =
            previous_proof.map(|proof| Box::pin(futures::future::ok(proof)) as BoxFuture<_>);

        let results: FuturesOrdered<_> = self
            .blocks
            .into_iter()
            .map(|block| {
                let block_number = block.get_block_number();
                info!("Proving block {block_number}");

                let (tx, rx) = oneshot::channel::<BenchmarkedGeneratedBlockProof>();

                // Prove the block
                let proof_output_dir = proof_output_dir.clone();
                let fut = block
                    .prove_and_benchmark(runtime, prev.take(), save_inputs_on_error)
                    .then(move |benchmarkproof| async move {
                        let benchmarkproof = benchmarkproof?;
                        let block_number = benchmarkproof.proof.b_height;

                        // Write latest generated proof to disk if proof_output_dir is provided
                        let return_proof: Option<BenchmarkedGeneratedBlockProof> =
                            if proof_output_dir.is_some() {
                                ProverInput::write_proof(proof_output_dir, &benchmarkproof.proof)
                                    .await?;
                                None
                            } else {
                                Some(benchmarkproof.clone())
                            };

                        if tx.send(benchmarkproof).is_err() {
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
