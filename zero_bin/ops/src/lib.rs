use anyhow::Result;
use once_cell::sync::Lazy;
use paladin::{
    operation::{Monoid, Operation},
    opkind_derive::OpKind,
};
use plonky_block_proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof, generate_txn_proof},
    proof_types::{
        AggregatableProof, GeneratedAggProof, GeneratedBlockProof, OtherBlockData, TxnProofGenIR,
    },
    prover_state::{ProverState, ProverStateBuilder},
};
use serde::{Deserialize, Serialize};

static P_STATE: Lazy<ProverState> = Lazy::new(|| ProverStateBuilder::default().build());

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct TxProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofInput<T> {
    pub data: T,
    pub other: OtherBlockData,
}

impl Operation for TxProof {
    type Input = ProofInput<TxnProofGenIR>;
    type Output = ProofInput<AggregatableProof>;
    type Kind = Ops;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let other_data = input.other;
        let result = generate_txn_proof(&P_STATE, input.data, other_data.clone())?;

        Ok(ProofInput {
            data: result.into(),
            other: other_data,
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct AggProof;

impl Monoid for AggProof {
    type Elem = ProofInput<AggregatableProof>;
    type Kind = Ops;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let other_data = a.other;
        let result = generate_agg_proof(&P_STATE, &a.data, &b.data, other_data.clone())?;

        Ok(ProofInput {
            data: result.into(),
            other: other_data,
        })
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
pub struct BlockProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockProofInput {
    pub data: GeneratedAggProof,
    pub other: OtherBlockData,
    pub prev: Option<GeneratedBlockProof>,
}

impl Operation for BlockProof {
    type Input = BlockProofInput;
    type Output = GeneratedBlockProof;
    type Kind = Ops;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(generate_block_proof(
            &P_STATE,
            input.prev.as_ref(),
            &input.data,
            input.other,
        )?)
    }
}

#[derive(OpKind, Debug, Clone, Copy, Deserialize, Serialize)]
pub enum Ops {
    TxProof(TxProof),
    AggProof(AggProof),
    BlockProof(BlockProof),
}
