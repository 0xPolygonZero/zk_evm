use common::prover_state::P_STATE;
use paladin::{
    operation::{FatalError, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use plonky_block_proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof, generate_txn_proof},
    proof_types::{AggregatableProof, GeneratedAggProof, GeneratedBlockProof},
    prover_state::ProverState,
};
use proof_protocol_decoder::types::{OtherBlockData, TxnProofGenIR};
use serde::{Deserialize, Serialize};

fn p_state() -> &'static ProverState {
    P_STATE.get().expect("Prover state is not initialized")
}

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct TxProof;

impl Operation for TxProof {
    type Input = TxnProofGenIR;
    type Output = AggregatableProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let result = generate_txn_proof(p_state(), input).map_err(FatalError::from)?;

        Ok(result.into())
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct AggProof {
    pub other: OtherBlockData,
}

impl Monoid for AggProof {
    type Elem = AggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let result =
            generate_agg_proof(p_state(), &a, &b, self.other.clone()).map_err(FatalError::from)?;

        Ok(result.into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct BlockProof {
    pub other: OtherBlockData,
    pub prev: Option<GeneratedBlockProof>,
}

impl Operation for BlockProof {
    type Input = GeneratedAggProof;
    type Output = GeneratedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(
            generate_block_proof(p_state(), self.prev.as_ref(), &input, self.other.clone())
                .map_err(FatalError::from)?,
        )
    }
}
