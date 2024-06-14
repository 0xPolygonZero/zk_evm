use std::future::Future;
use std::path::PathBuf;

use alloy::primitives::{BlockNumber, U256};
use anyhow::{Context, Result};
use common::fs::generate_block_proof_file_name;
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
        save_inputs_on_error: bool,
    ) -> Result<GeneratedBlockProof> {
        use anyhow::Context as _;

        let block_number = self.get_block_number();
        info!("Proving block {block_number}");

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
    pub async fn prove(
        self,
        runtime: &Runtime,
        previous_proof: Option<GeneratedBlockProof>,
        save_inputs_on_error: bool,
        proof_output_dir: Option<PathBuf>,
    ) -> Result<Vec<BlockNumber>> {
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

                        // Write latest generated proof to disk or stdout
                        ProverInput::write_proof(proof_output_dir, &proof).await?;

                        if tx.send(proof).is_err() {
                            anyhow::bail!("Failed to send proof");
                        }

                        Ok(block_number)
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
