use std::{ops::RangeInclusive, time::Instant};

use common::prover_state::p_state;
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
use trace_decoder::types::{BlockHeight, TxnProofGenIR};
use tracing::{event, info_span, Level};

registry!();

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct TxProof;

fn run_and_wrap_closure_in_elapsed_span<F, O>(f: F, ident: String) -> Result<O>
where
    F: Fn() -> Result<O>,
{
    let _span = info_span!("proof generation", ident).entered();
    let start = Instant::now();

    let proof = f()?;

    event!(Level::INFO, "Proof {:.4} took {:?}", ident, start.elapsed());
    Ok(proof)
}

#[cfg(not(feature = "test_only"))]
impl Operation for TxProof {
    type Input = TxnProofGenIR;
    type Output = proof_gen::proof_types::AggregatableProof;

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let txn_ident = Self::txn_ident(&input);

        let proof = run_and_wrap_closure_in_elapsed_span(
            || {
                common::prover_state::p_manager()
                    .generate_txn_proof(input.clone())
                    .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate).into())
            },
            txn_ident,
        )?;

        Ok(proof.into())
    }
}

#[cfg(feature = "test_only")]
impl Operation for TxProof {
    type Input = TxnProofGenIR;
    type Output = ();

    fn execute(&self, input: Self::Input) -> Result<Self::Output> {
        let txn_ident = Self::txn_ident(&input);

        run_and_wrap_closure_in_elapsed_span(
            || {
                evm_arithmetization::prover::testing::simulate_execution::<proof_gen::types::Field>(
                    input.clone(),
                )
                .map_err(|err| FatalError::from_anyhow(err, FatalStrategy::Terminate).into())
            },
            txn_ident,
        )?;

        Ok(())
    }
}

impl TxProof {
    fn txn_ident(ir: &TxnProofGenIR) -> String {
        let txn_hash_str = ir
            .signed_txn
            .as_ref()
            .map(|txn| format!("{:x}", keccak(txn)))
            .unwrap_or_else(|| "Dummy".to_string());

        format!(
            "Txn b{} - {} ({})",
            ir.block_metadata.block_number, ir.txn_number_before, txn_hash_str
        )
    }
}

#[derive(Deserialize, Serialize, RemoteExecute)]
pub struct AggProof;

impl Monoid for AggProof {
    type Elem = AggregatableProof;

    fn combine(&self, a: Self::Elem, b: Self::Elem) -> Result<Self::Elem> {
        let ident = Self::agg_ident(&a, &b);
        let result = run_and_wrap_closure_in_elapsed_span(
            || generate_agg_proof(p_state(), &a, &b).map_err(|e| FatalError::from(e).into()),
            ident,
        )?;

        Ok(result.into())
    }

    fn empty(&self) -> Self::Elem {
        // Expect that empty blocks are padded.
        unimplemented!("empty agg proof")
    }
}

impl AggProof {
    fn agg_ident(a: &AggregatableProof, b: &AggregatableProof) -> String {
        let b_height = b_height_from_aggregatable_proof(a);
        let a_range = proof_range_from_aggregatable_proof(a);
        let b_range = proof_range_from_aggregatable_proof(b);

        format!(
            "Agg b{} - {}..={}",
            b_height,
            *a_range.start(),
            *b_range.end()
        )
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
        let ident = Self::block_ident(&input);

        run_and_wrap_closure_in_elapsed_span(
            || {
                generate_block_proof(p_state(), self.prev.as_ref(), &input)
                    .map_err(|e| FatalError::from(e).into())
            },
            ident,
        )
    }
}

impl BlockProof {
    fn block_ident(p: &GeneratedAggProof) -> String {
        let b_height = p.p_vals.block_metadata.block_number;
        let b_range = aggregated_proof_range(p);

        format!(
            "Block b{} ({}..={})",
            b_height,
            *b_range.start(),
            *b_range.end()
        )
    }
}

fn proof_range_from_aggregatable_proof(p: &AggregatableProof) -> RangeInclusive<usize> {
    match p {
        AggregatableProof::Txn(info) => {
            let txn_idx = info.p_vals.extra_block_data.txn_number_before.as_usize();
            txn_idx..=txn_idx
        }
        AggregatableProof::Agg(info) => aggregated_proof_range(info),
    }
}

fn aggregated_proof_range(p: &GeneratedAggProof) -> RangeInclusive<usize> {
    p.p_vals.extra_block_data.txn_number_before.as_usize()
        ..=p.p_vals.extra_block_data.txn_number_after.as_usize()
}

fn b_height_from_aggregatable_proof(p: &AggregatableProof) -> BlockHeight {
    match p {
        AggregatableProof::Txn(info) => info.p_vals.block_metadata.block_number.as_u64(),
        AggregatableProof::Agg(info) => info.p_vals.block_metadata.block_number.as_u64(),
    }
}
