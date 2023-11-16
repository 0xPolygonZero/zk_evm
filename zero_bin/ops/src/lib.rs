use once_cell::sync::Lazy;
use paladin::{
    operation::{FatalError, Monoid, Operation, Result},
    opkind_derive::OpKind,
};
use plonky_block_proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof, generate_txn_proof},
    proof_types::{AggregatableProof, GeneratedAggProof, GeneratedBlockProof},
    prover_state::{ProverState, ProverStateBuilder},
};
use proof_protocol_decoder::types::{OtherBlockData, TxnProofGenIR};
use serde::{Deserialize, Serialize};

static P_STATE: Lazy<ProverState> = Lazy::new(|| ProverStateBuilder::default().build());

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct TxProof;

impl Operation for TxProof {
    type Input = TxnProofGenIR;
    type Output = AggregatableProof;
    type Kind = Ops;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let result = generate_txn_proof(&P_STATE, input).map_err(FatalError::from)?;

        Ok(result.into())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AggProof {
    pub other: OtherBlockData,
}

impl Monoid for AggProof {
    type Elem = AggregatableProof;
    type Kind = Ops;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let result =
            generate_agg_proof(&P_STATE, &a, &b, self.other.clone()).map_err(FatalError::from)?;

        Ok(result.into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockProof {
    pub other: OtherBlockData,
    pub prev: Option<GeneratedBlockProof>,
}

impl Operation for BlockProof {
    type Input = GeneratedAggProof;
    type Output = GeneratedBlockProof;
    type Kind = Ops;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(
            generate_block_proof(&P_STATE, self.prev.as_ref(), &input, self.other.clone())
                .map_err(FatalError::from)?,
        )
    }
}

#[derive(OpKind, Debug, Clone, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum Ops {
    TxProof(TxProof),
    AggProof(AggProof),
    BlockProof(BlockProof),
}
