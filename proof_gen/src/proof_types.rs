//! This module defines the various proof types used throughout the block proof
//! generation process.

use evm_arithmetization::{
    fixed_recursive_verifier::{extract_block_final_public_values, extract_two_to_one_block_hash},
    proof::PublicValues,
    BlockHeight,
};
use plonky2::plonk::config::Hasher as _;
use serde::{Deserialize, Serialize};

use crate::types::{Hash, Hasher, PlonkyProofIntern};

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

/// An aggregation block proof along with its hashed public values, for proper
/// connection with other proofs.
///
/// Aggregation block proofs can represent any aggregation of independent
/// blocks.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggBlockProof {
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
pub enum BatchAggregatableProof {
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

    pub(crate) const fn intern(&self) -> &PlonkyProofIntern {
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

impl From<GeneratedTxnAggProof> for BatchAggregatableProof {
    fn from(v: GeneratedTxnAggProof) -> Self {
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

    pub(crate) const fn is_agg(&self) -> bool {
        match self {
            AggregatableBlockProof::Block(_) => false,
            AggregatableBlockProof::Agg(_) => true,
        }
    }

    pub(crate) const fn intern(&self) -> &PlonkyProofIntern {
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
