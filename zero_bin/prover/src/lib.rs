use anyhow::{bail, Result};
use ethereum_types::U256;
use ops::{AggProof, BlockProof, TxProof};
use paladin::{
    directive::{Directive, IndexedStream, Literal},
    runtime::Runtime,
};
use plonky_block_proof_gen::{
    proof_types::{AggregatableProof, GeneratedBlockProof},
    types::PlonkyProofIntern,
};
use protocol_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};
use serde::{Deserialize, Serialize};
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
        self.other_data.b_data.b_meta.block_number
    }

    pub async fn prove(
        self,
        runtime: &Runtime,
        previous: Option<PlonkyProofIntern>,
    ) -> Result<GeneratedBlockProof> {
        let block_number = self.get_block_number();
        info!("Proving block {block_number}");

        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
        )?;

        let agg_proof = IndexedStream::from(txs)
            .map(&TxProof)
            .fold(&AggProof)
            .run(runtime)
            .await?;

        if let AggregatableProof::Agg(proof) = agg_proof {
            let prev = previous.map(|p| GeneratedBlockProof {
                b_height: block_number.as_u64() - 1,
                intern: p,
            });

            let block_proof = Literal(proof)
                .map(&BlockProof { prev })
                .run(runtime)
                .await?;

            info!("Successfully proved block {block_number}");
            Ok(block_proof.0)
        } else {
            bail!("AggProof is is not GeneratedAggProof")
        }
    }
}
