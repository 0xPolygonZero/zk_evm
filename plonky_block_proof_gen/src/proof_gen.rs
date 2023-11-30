use plonky2::util::timing::TimingTree;
use plonky2_evm::{
    all_stark::AllStark,
    config::StarkConfig,
    proof::{ExtraBlockData, PublicValues},
};
use proof_protocol_decoder::{
    proof_gen_types::ProofBeforeAndAfterDeltas,
    types::{OtherBlockData, TxnProofGenIR},
};

use crate::{
    proof_types::{
        create_extra_block_data, AggregatableProof, GeneratedAggProof, GeneratedBlockProof,
        GeneratedTxnProof, ProofCommon,
    },
    prover_state::ProverState,
    types::{PlonkyProofIntern, ProofUnderlyingTxns},
};

pub type ProofGenResult<T> = Result<T, ProofGenError>;

// Plonky2 is still using `anyhow` for proof gen, and since this is a library,
// it's probably best if we at least convert it to a `String`.
#[derive(Debug)]
pub struct ProofGenError(pub String);

impl std::fmt::Display for ProofGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl std::error::Error for ProofGenError {}

impl From<String> for ProofGenError {
    fn from(v: String) -> Self {
        Self(v)
    }
}

/// Generate a txn proof from proof IR data.
pub fn generate_txn_proof(
    p_state: &ProverState,
    start_info: TxnProofGenIR,
) -> ProofGenResult<GeneratedTxnProof> {
    let b_height = start_info.b_height();
    let txn_idx = start_info.txn_idx;
    let deltas = start_info.deltas();

    let (txn_proof_intern, p_vals) = p_state
        .state
        .prove_root(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            start_info.gen_inputs,
            &mut TimingTree::default(),
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height,
        deltas,
        roots_before: p_vals.trie_roots_before,
        roots_after: p_vals.trie_roots_after,
    };

    Ok(GeneratedTxnProof {
        txn_idx,
        common,
        intern: txn_proof_intern,
    })
}

/// Generate a agg proof from two child proofs.
///
/// Note that the child proofs may be either txn or agg proofs.
pub fn generate_agg_proof(
    p_state: &ProverState,
    lhs_child: &AggregatableProof,
    rhs_child: &AggregatableProof,
    other_data: OtherBlockData,
) -> ProofGenResult<GeneratedAggProof> {
    let expanded_agg_proofs = expand_aggregatable_proofs(lhs_child, rhs_child, other_data);

    let (agg_proof_intern, p_vals) = p_state
        .state
        .prove_aggregation(
            expanded_agg_proofs.lhs.is_agg,
            expanded_agg_proofs.lhs.intern,
            expanded_agg_proofs.p_vals_lhs,
            expanded_agg_proofs.rhs.is_agg,
            expanded_agg_proofs.rhs.intern,
            expanded_agg_proofs.p_vals_rhs,
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height: lhs_child.b_height(),
        deltas: expanded_agg_proofs.combined_deltas,
        roots_before: p_vals.trie_roots_before,
        roots_after: p_vals.trie_roots_after,
    };

    Ok(GeneratedAggProof {
        common,
        underlying_txns: lhs_child
            .underlying_txns()
            .combine(&rhs_child.underlying_txns()),
        intern: agg_proof_intern,
    })
}

struct ExpandedAggregatableProofs<'a> {
    p_vals_lhs: PublicValues,
    p_vals_rhs: PublicValues,
    lhs: ExpandedAggregatableProof<'a>,
    rhs: ExpandedAggregatableProof<'a>,
    combined_deltas: ProofBeforeAndAfterDeltas,
}

struct ExpandedAggregatableProof<'a> {
    intern: &'a PlonkyProofIntern,
    is_agg: bool,
}

// TODO: Remove or simplify, as most of this work is occurring inside plonky2
// now.
fn expand_aggregatable_proofs<'a>(
    lhs_child: &'a AggregatableProof,
    rhs_child: &'a AggregatableProof,
    other_data: OtherBlockData,
) -> ExpandedAggregatableProofs<'a> {
    let (expanded_lhs, lhs_common) = expand_aggregatable_proof(lhs_child);
    let (expanded_rhs, rhs_common) = expand_aggregatable_proof(rhs_child);

    let lhs_extra_data =
        create_extra_block_data_for_child(lhs_common, &other_data, &lhs_child.underlying_txns());

    let p_vals_lhs = PublicValues {
        trie_roots_before: lhs_common.roots_before.clone(),
        trie_roots_after: lhs_common.roots_after.clone(),
        block_metadata: other_data.b_data.b_meta.clone(),
        block_hashes: other_data.b_data.b_hashes.clone(),
        extra_block_data: lhs_extra_data,
    };

    let rhs_extra_data =
        create_extra_block_data_for_child(rhs_common, &other_data, &rhs_child.underlying_txns());

    let p_vals_rhs = PublicValues {
        trie_roots_before: rhs_common.roots_before.clone(),
        trie_roots_after: rhs_common.roots_after.clone(),
        block_metadata: other_data.b_data.b_meta,
        block_hashes: other_data.b_data.b_hashes,
        extra_block_data: rhs_extra_data,
    };

    let combined_deltas = merge_lhs_and_rhs_deltas(&lhs_common.deltas, &rhs_common.deltas);

    ExpandedAggregatableProofs {
        p_vals_lhs,
        p_vals_rhs,
        lhs: expanded_lhs,
        rhs: expanded_rhs,
        combined_deltas,
    }
}

fn create_extra_block_data_for_child(
    common: &ProofCommon,
    other_data: &OtherBlockData,
    txn_range: &ProofUnderlyingTxns,
) -> ExtraBlockData {
    create_extra_block_data(
        common.deltas.clone(),
        other_data.genesis_state_trie_root,
        txn_range.txn_idxs.start,
        txn_range.txn_idxs.end,
    )
}

fn merge_lhs_and_rhs_deltas(
    lhs: &ProofBeforeAndAfterDeltas,
    rhs: &ProofBeforeAndAfterDeltas,
) -> ProofBeforeAndAfterDeltas {
    ProofBeforeAndAfterDeltas {
        gas_used_before: lhs.gas_used_before,
        gas_used_after: rhs.gas_used_after,
    }
}

fn expand_aggregatable_proof(p: &AggregatableProof) -> (ExpandedAggregatableProof, &ProofCommon) {
    let (intern, is_agg, common) = match p {
        AggregatableProof::Txn(txn_intern) => (&txn_intern.intern, false, &txn_intern.common),
        AggregatableProof::Agg(agg_intern) => (&agg_intern.intern, true, &agg_intern.common),
    };

    let expanded = ExpandedAggregatableProof { intern, is_agg };

    (expanded, common)
}

/// Generate a block proof.
///
/// Note that `prev_opt_parent_b_proof` is able to be `None` on checkpoint
/// heights.
pub fn generate_block_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedAggProof,
    other_data: OtherBlockData,
) -> ProofGenResult<GeneratedBlockProof> {
    let b_height = curr_block_agg_proof.common.b_height;
    let parent_intern = prev_opt_parent_b_proof.map(|p| &p.intern);

    let extra_block_data = create_extra_block_data(
        curr_block_agg_proof.common.deltas.clone(),
        other_data.genesis_state_trie_root,
        curr_block_agg_proof.underlying_txns.txn_idxs.start,
        curr_block_agg_proof.underlying_txns.txn_idxs.end,
    );

    let p_vals = PublicValues {
        trie_roots_before: curr_block_agg_proof.common.roots_before.clone(),
        trie_roots_after: curr_block_agg_proof.common.roots_after.clone(),
        block_metadata: other_data.b_data.b_meta,
        block_hashes: other_data.b_data.b_hashes,
        extra_block_data,
    };

    let (b_proof_intern, _) = p_state
        .state
        .prove_block(parent_intern, &curr_block_agg_proof.intern, p_vals)
        .map_err(|err| err.to_string())?;

    Ok(GeneratedBlockProof {
        b_height,
        intern: b_proof_intern,
    })
}
