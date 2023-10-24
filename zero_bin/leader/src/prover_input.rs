use anyhow::{bail, Result};
use ops::{AggProof, BlockProof, BlockProofInput, ProofInput, TxProof};
use paladin::{
    directive::{Directive, IndexedStream, Literal},
    runtime::Runtime,
};
use plonky_block_proof_gen::proof_types::{
    AggregatableProof, GeneratedBlockProof, OtherBlockData, TxnProofGenIR,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct ProverInput {
    txs: Vec<TxnProofGenIR>,
    other_data: OtherBlockData,
}

impl ProverInput {
    pub(crate) async fn prove(self, runtime: &Runtime) -> Result<GeneratedBlockProof> {
        let other_data = self.other_data;
        let txs_zipped = self.txs.into_iter().map(move |tx| ProofInput {
            data: tx,
            other: other_data.clone(),
        });
        let agg_proof = IndexedStream::from(txs_zipped)
            .map(TxProof)
            .fold(AggProof)
            .run(runtime)
            .await?;

        if let AggregatableProof::Agg(p) = agg_proof.data {
            let block_proof = Literal(BlockProofInput {
                data: p,
                other: agg_proof.other,
                prev: None,
            })
            .map(BlockProof)
            .run(runtime)
            .await?;

            Ok(block_proof.0)
        } else {
            bail!("AggProof is is not GeneratedAggProof")
        }
    }
}
