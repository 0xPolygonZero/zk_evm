//! This module defines the various proof types used throughout the block proof
//! generation process.

use evm_arithmetization::{
    proof::FinalPublicValues, BlockHeight, ChainID, HashOrPV, ProofWithPublicInputs, PublicValues,
};
use serde::{Deserialize, Serialize};

/// A transaction proof along with its public values, for proper connection with
/// contiguous proofs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedSegmentProof {
    /// Public values of this transaction proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// A segment aggregation proof along with its public values, for proper
/// connection with contiguous proofs.
///
/// Aggregation proofs can represent any contiguous range of two or more
/// segments, up to an entire transaction.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedSegmentAggProof {
    /// Public values of this aggregation proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// A transaction aggregation proof along with its public values, for proper
/// connection with contiguous proofs.
///
/// Transaction agregation proofs can represent any contiguous range of two or
/// more transactions, up to an entire block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBatchAggProof {
    /// Public values of this transaction aggregation proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// A block proof along with the block height against which this proof ensures
/// the validity since the last proof checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    /// Associated block height.
    pub b_height: BlockHeight,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// A wrapped block proof along with the block height against which this proof
/// ensures the validity since the last proof checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedWrappedBlockProof {
    /// Associated block height.
    pub b_height: BlockHeight,
    /// Associated chain ID.
    pub chain_id: ChainID,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// An aggregation block proof along with its public values, for proper
/// verification by a third-party.
///
/// Aggregation block proofs can represent any aggregation of independent
/// blocks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggBlockProof {
    /// Public values of this aggregation proof.
    pub p_vals: HashOrPV,
    /// Underlying plonky2 proof.
    pub intern: ProofWithPublicInputs,
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SegmentAggregatableProof {
    /// The underlying proof is a segment proof.
    Seg(GeneratedSegmentProof),
    /// The underlying proof is an aggregation proof.
    Agg(GeneratedSegmentAggProof),
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BatchAggregatableProof {
    /// The underlying proof is a segment proof. It first needs to be aggregated
    /// with another segment proof, or a dummy one.
    Segment(GeneratedSegmentProof),
    /// The underlying proof is a transaction proof.
    Txn(GeneratedSegmentAggProof),
    /// The underlying proof is an aggregation proof.
    Agg(GeneratedBatchAggProof),
}

impl SegmentAggregatableProof {
    pub(crate) fn public_values(&self) -> PublicValues {
        match self {
            SegmentAggregatableProof::Seg(info) => info.p_vals.clone(),
            SegmentAggregatableProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            SegmentAggregatableProof::Seg(_) => false,
            SegmentAggregatableProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &ProofWithPublicInputs {
        match self {
            SegmentAggregatableProof::Seg(info) => &info.intern,
            SegmentAggregatableProof::Agg(info) => &info.intern,
        }
    }
}

impl BatchAggregatableProof {
    pub(crate) fn public_values(&self) -> PublicValues {
        match self {
            BatchAggregatableProof::Segment(info) => info.p_vals.clone(),
            BatchAggregatableProof::Txn(info) => info.p_vals.clone(),
            BatchAggregatableProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            BatchAggregatableProof::Segment(_) => false,
            BatchAggregatableProof::Txn(_) => false,
            BatchAggregatableProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &ProofWithPublicInputs {
        match self {
            BatchAggregatableProof::Segment(info) => &info.intern,
            BatchAggregatableProof::Txn(info) => &info.intern,
            BatchAggregatableProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedSegmentProof> for SegmentAggregatableProof {
    fn from(v: GeneratedSegmentProof) -> Self {
        Self::Seg(v)
    }
}

impl From<GeneratedSegmentAggProof> for SegmentAggregatableProof {
    fn from(v: GeneratedSegmentAggProof) -> Self {
        Self::Agg(v)
    }
}

impl From<GeneratedSegmentAggProof> for BatchAggregatableProof {
    fn from(v: GeneratedSegmentAggProof) -> Self {
        Self::Txn(v)
    }
}

impl From<GeneratedBatchAggProof> for BatchAggregatableProof {
    fn from(v: GeneratedBatchAggProof) -> Self {
        Self::Agg(v)
    }
}

impl From<SegmentAggregatableProof> for BatchAggregatableProof {
    fn from(v: SegmentAggregatableProof) -> Self {
        match v {
            SegmentAggregatableProof::Agg(agg) => BatchAggregatableProof::Txn(agg),
            SegmentAggregatableProof::Seg(seg) => BatchAggregatableProof::Segment(seg),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableBlockProof {
    /// The underlying proof is a single wrapped block proof.
    Block(GeneratedWrappedBlockProof),
    /// The underlying proof is an aggregated proof.
    Agg(GeneratedAggBlockProof),
}

impl AggregatableBlockProof {
    pub(crate) fn public_values(&self) -> HashOrPV {
        match self {
            AggregatableBlockProof::Block(info) => HashOrPV::Val(
                FinalPublicValues::from_public_inputs(&info.intern.public_inputs),
            ),
            AggregatableBlockProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            AggregatableBlockProof::Block(_) => false,
            AggregatableBlockProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &ProofWithPublicInputs {
        match self {
            AggregatableBlockProof::Block(info) => &info.intern,
            AggregatableBlockProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedWrappedBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedWrappedBlockProof) -> Self {
        Self::Block(v)
    }
}

impl From<GeneratedAggBlockProof> for AggregatableBlockProof {
    fn from(v: GeneratedAggBlockProof) -> Self {
        Self::Agg(v)
    }
}
