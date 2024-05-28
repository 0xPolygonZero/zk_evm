use alloy::primitives::U256;
use anyhow::Result;
#[cfg(feature = "test_only")]
use futures::stream::TryStreamExt;
use num_traits::ToPrimitive as _;
use ops::TxProof;
use paladin::{
    directive::{Directive, IndexedStream},
    runtime::Runtime,
};
use proof_gen::{proof_types::GeneratedBlockProof, types::PlonkyProofIntern};
use serde::{Deserialize, Serialize};
use trace_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};
use tracing::info;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}
fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

impl ProverInput {
    pub fn get_block_number(&self) -> U256 {
        self.other_data.b_data.b_meta.block_number.into()
    }

    #[cfg(not(feature = "test_only"))]
    pub async fn prove(
        self,
        runtime: &Runtime,
        previous: Option<PlonkyProofIntern>,
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
            let prev = previous.map(|p| GeneratedBlockProof {
                b_height: block_number - 1,
                intern: p,
            });

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
        _previous: Option<PlonkyProofIntern>,
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
