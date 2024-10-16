//! This module defines the various proof types used throughout the block proof
//! generation process.

use evm_arithmetization::{
    fixed_recursive_verifier::{extract_block_final_public_values, extract_two_to_one_block_hash},
    BlockHeight, Hash, Hasher, ProofWithPublicInputs, ProofWithPublicValues, ProverOutputData,
};
use plonky2::plonk::config::Hasher as _;
use serde::{Deserialize, Serialize};

/// A block proof along with the block height against which this proof ensures
/// the validity since the last proof checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    /// Associated block height.
    pub b_height: BlockHeight,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// An aggregation block proof along with its hashed public values, for proper
/// connection with other proofs.
///
/// Aggregation block proofs can represent any aggregation of independent
/// blocks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggBlockProof {
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SegmentAggregatableProof {
    /// The underlying proof is a segment proof.
    Segment(ProverOutputData),
    /// The underlying proof is an aggregated segment proof.
    Agg(ProverOutputData),
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BatchAggregatableProof {
    /// The underlying proof is a segment proof. It first needs to be aggregated
    /// with another segment proof, or a dummy one.
    Segment(ProverOutputData),
    /// The underlying proof is an aggregated segment proof.
    SegmentAgg(ProverOutputData),
    /// The underlying proof is an aggregated batch proof.
    BatchAgg(ProofWithPublicValues),
}

impl SegmentAggregatableProof {
    pub(crate) fn as_prover_output_data(&self) -> &ProverOutputData {
        match self {
            SegmentAggregatableProof::Segment(info) => &info,
            SegmentAggregatableProof::Agg(info) => &info,
        }
    }

    pub(crate) fn proof_with_pvs(&self) -> ProofWithPublicValues {
        match self {
            SegmentAggregatableProof::Segment(info) => info.proof_with_pvs.clone(),
            SegmentAggregatableProof::Agg(info) => info.proof_with_pvs.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            SegmentAggregatableProof::Segment(info) => info.is_agg,
            SegmentAggregatableProof::Agg(info) => info.is_agg,
        }
    }
}

impl BatchAggregatableProof {
    pub(crate) fn proof_with_pvs(&self) -> &ProofWithPublicValues {
        match self {
            BatchAggregatableProof::Segment(info) => &info.proof_with_pvs,
            BatchAggregatableProof::SegmentAgg(info) => &info.proof_with_pvs,
            BatchAggregatableProof::BatchAgg(info) => info,
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            BatchAggregatableProof::Segment(info) => info.is_agg,
            BatchAggregatableProof::SegmentAgg(info) => info.is_agg,
            BatchAggregatableProof::BatchAgg(_) => true,
        }
    }
}

impl From<SegmentAggregatableProof> for BatchAggregatableProof {
    fn from(v: SegmentAggregatableProof) -> Self {
        match v {
            SegmentAggregatableProof::Agg(agg) => BatchAggregatableProof::SegmentAgg(agg),
            SegmentAggregatableProof::Segment(seg) => BatchAggregatableProof::Segment(seg),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableBlockProof {
    /// The underlying proof is a single block proof.
    Block(GeneratedBlockProof),
    /// The underlying proof is an aggregated proof.
    Agg(GeneratedAggBlockProof),
}

impl AggregatableBlockProof {
    pub fn pv_hash(&self) -> Hash {
        match self {
            AggregatableBlockProof::Block(info) => {
                let pv = extract_block_final_public_values(&info.intern.public_inputs);
                Hasher::hash_no_pad(pv)
            }
            AggregatableBlockProof::Agg(info) => {
                let hash = extract_two_to_one_block_hash(&info.intern.public_inputs);
                Hash::from_partial(hash)
            }
        }
    }

    // TODO(Robin): https://github.com/0xPolygonZero/zk_evm/issues/387
    #[allow(unused)]
    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            AggregatableBlockProof::Block(_) => false,
            AggregatableBlockProof::Agg(_) => true,
        }
    }

    // TODO(Robin): https://github.com/0xPolygonZero/zk_evm/issues/387
    #[allow(unused)]
    pub(crate) const fn intern(&self) -> &ProofWithPublicInputs {
        match self {
            AggregatableBlockProof::Block(info) => &info.intern,
            AggregatableBlockProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedBlockProof) -> Self {
        Self::Block(v)
    }
}

impl From<GeneratedAggBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedAggBlockProof) -> Self {
        Self::Agg(v)
    }
}
