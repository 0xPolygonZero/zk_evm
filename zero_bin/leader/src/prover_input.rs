use anyhow::{bail, Result};
use ops::{AggProof, BlockProof, TxProof};
use paladin::{
    directive::{Directive, IndexedStream, Literal},
    runtime::Runtime,
};
use plonky_block_proof_gen::proof_types::{AggregatableProof, GeneratedBlockProof};
use proof_protocol_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct ProverInput {
    block_trace: BlockTrace,
    other_data: OtherBlockData,
}

fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

impl ProverInput {
    pub(crate) async fn prove(self, runtime: &Runtime) -> Result<GeneratedBlockProof> {
        let other_data = self.other_data;
        let txs = self.block_trace.into_txn_proof_gen_ir(
            &ProcessingMeta::new(resolve_code_hash_fn),
            other_data.clone(),
        )?;

        let agg_proof = IndexedStream::from(txs)
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
