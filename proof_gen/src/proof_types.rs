//! This module defines the various proof types used throughout the block proof
//! generation process.

use evm_arithmetization::{proof::PublicValues, BlockHeight};
use serde::{Deserialize, Serialize};

use crate::types::PlonkyProofIntern;

/// A transaction proof along with its public values, for proper connection with
/// contiguous proofs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedSegmentProof {
    /// Public values of this transaction proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
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
    pub intern: PlonkyProofIntern,
}

/// A transaction aggregation proof along with its public values, for proper
/// connection with contiguous proofs.
///
/// Transaction agregation proofs can represent any contiguous range of two or
/// more transactions, up to an entire block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedTxnAggProof {
    /// Public values of this transaction aggregation proof.
    pub p_vals: PublicValues,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
}

/// A block proof along with the block height against which this proof ensures
/// the validity since the last proof checkpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    /// Associated block height.
    pub b_height: BlockHeight,
    /// Underlying plonky2 proof.
    pub intern: PlonkyProofIntern,
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
pub enum TxnAggregatableProof {
    /// The underlying proof is a segment proof. It first needs to be aggregated
    /// with another segment proof, or a dummy one.
    Segment(GeneratedSegmentProof),
    /// The underlying proof is a transaction proof.
    Txn(GeneratedSegmentAggProof),
    /// The underlying proof is an aggregation proof.
    Agg(GeneratedTxnAggProof),
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

    pub(crate) const fn intern(&self) -> &PlonkyProofIntern {
        match self {
            SegmentAggregatableProof::Seg(info) => &info.intern,
            SegmentAggregatableProof::Agg(info) => &info.intern,
        }
    }
}

impl TxnAggregatableProof {
    pub(crate) fn public_values(&self) -> PublicValues {
        match self {
            TxnAggregatableProof::Segment(info) => info.p_vals.clone(),
            TxnAggregatableProof::Txn(info) => info.p_vals.clone(),
            TxnAggregatableProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) fn is_agg(&self) -> bool {
        match self {
            TxnAggregatableProof::Segment(_) => false,
            TxnAggregatableProof::Txn(_) => false,
            TxnAggregatableProof::Agg(_) => true,
        }
    }

    pub(crate) fn intern(&self) -> &PlonkyProofIntern {
        match self {
            TxnAggregatableProof::Segment(info) => &info.intern,
            TxnAggregatableProof::Txn(info) => &info.intern,
            TxnAggregatableProof::Agg(info) => &info.intern,
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

impl From<GeneratedSegmentAggProof> for TxnAggregatableProof {
    fn from(v: GeneratedSegmentAggProof) -> Self {
        Self::Txn(v)
    }
}

impl From<GeneratedTxnAggProof> for TxnAggregatableProof {
    fn from(v: GeneratedTxnAggProof) -> Self {
        Self::Agg(v)
    }
}

impl From<SegmentAggregatableProof> for TxnAggregatableProof {
    fn from(v: SegmentAggregatableProof) -> Self {
        match v {
            SegmentAggregatableProof::Agg(agg) => TxnAggregatableProof::Txn(agg),
            SegmentAggregatableProof::Seg(seg) => TxnAggregatableProof::Segment(seg),
        }
    }
}
