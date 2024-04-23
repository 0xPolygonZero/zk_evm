use std::time::Instant;

use common::prover_state::p_state;
use evm_arithmetization::GenerationInputs;
use keccak_hash::keccak;
use paladin::{
    operation::{FatalError, FatalStrategy, Monoid, Operation, Result},
    registry, RemoteExecute,
};
use proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof},
    proof_types::{AggregatableProof, GeneratedAggProof, GeneratedBlockProof},
};
use serde::{Deserialize, Serialize};
use tracing::{event, info_span, Level};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct TxProof;

#[cfg(not(feature = "test_only"))]
impl Operation for TxProof {
    type Input = GenerationInputs;
    type Output = proof_gen::proof_types::AggregatableProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let proof = Self::run_and_wrap_txn_proof_in_elapsed_span(
            || {
                common::prover_state::p_manager()
                    .generate_txn_proof(input.clone())
                    .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate).into())
            },
            &input,
        )?;

        Ok(proof.into())
    }
}

#[cfg(feature = "test_only")]
impl Operation for TxProof {
    type Input = GenerationInputs;
    type Output = ();

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Self::run_and_wrap_txn_proof_in_elapsed_span(
            || {
                evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                    input.clone(),
                )
                .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate).into())
            },
            &input,
        )?;

        Ok(())
    }
}

impl TxProof {
    fn run_and_wrap_txn_proof_in_elapsed_span<F, O>(f: F, ir: &GenerationInputs) -> Result<O>
    where
        F: Fn() -> Result<O>,
    {
        let id = format!(
            "b{} - {}",
            ir.block_metadata.block_number, ir.txn_number_before
        );

        let _span = info_span!("p_gen", id).entered();
        let start = Instant::now();

        let proof = f()?;

        let txn_hash_str = ir
            .signed_txn
            .as_ref()
            .map(|txn| format!("{:x}", keccak(txn)))
            .unwrap_or_else(|| "Dummy".to_string());

        event!(
            Level::INFO,
            "txn proof ({}) took {:?}",
            txn_hash_str,
            start.elapsed()
        );
        Ok(proof)
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct AggProof;

impl Monoid for AggProof {
    type Elem = AggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let result = generate_agg_proof(p_state(), &a, &b).map_err(FatalError::from)?;

        Ok(result.into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct BlockProof {
    pub prev: Option<GeneratedBlockProof>,
}

impl Operation for BlockProof {
    type Input = GeneratedAggProof;
    type Output = GeneratedBlockProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        Ok(
            generate_block_proof(p_state(), self.prev.as_ref(), &input)
                .map_err(FatalError::from)?,
        )
    }
}
