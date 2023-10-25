use anyhow::{bail, Result};
use ops::{AggProof, BlockProof, TxProof};
use paladin::{
    directive::{Directive, IndexedStream, Literal},
    runtime::Runtime,
};
use plonky_block_proof_gen::proof_types::{AggregatableProof, GeneratedBlockProof};
use proof_protocol_decoder::types::{OtherBlockData, TxnProofGenIR};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct ProverInput {
    txs: Vec<TxnProofGenIR>,
    other_data: OtherBlockData,
}

impl ProverInput {
    pub(crate) async fn prove(self, runtime: &Runtime) -> Result<GeneratedBlockProof> {
        let other_data = self.other_data;

        let agg_proof = IndexedStream::from(self.txs)
            .map(TxProof)
            .fold(AggProof {
                other: other_data.clone(),
            })
            .run(runtime)
            .await?;

        if let AggregatableProof::Agg(proof) = agg_proof {
            let block_proof = Literal(proof)
                .map(BlockProof {
                    prev: None,
                    other: other_data,
                })
                .run(runtime)
                .await?;

            Ok(block_proof.0)
        } else {
            bail!("AggProof is is not GeneratedAggProof")
        }
    }
}
