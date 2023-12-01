use plonky2_evm::proof::PublicValues;
use proof_protocol_decoder::types::BlockHeight;
use serde::{Deserialize, Serialize};

use crate::types::PlonkyProofIntern;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedTxnProof {
    pub p_vals: PublicValues,
    pub intern: PlonkyProofIntern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedAggProof {
    pub p_vals: PublicValues,
    pub intern: PlonkyProofIntern,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GeneratedBlockProof {
    pub b_height: BlockHeight,
    pub intern: PlonkyProofIntern,
}

/// Sometimes we don't care about the underlying proof type and instead only if
/// we can combine it into an agg proof. For these cases, we want to abstract
/// away whether or not the proof was a txn or agg proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AggregatableProof {
    Txn(GeneratedTxnProof),
    Agg(GeneratedAggProof),
}

impl AggregatableProof {
    pub(crate) fn public_values(&self) -> PublicValues {
        match self {
            AggregatableProof::Txn(info) => info.p_vals.clone(),
            AggregatableProof::Agg(info) => info.p_vals.clone(),
        }
    }

    pub(crate) fn is_agg(&self) -> bool {
        match self {
            AggregatableProof::Txn(_) => false,
            AggregatableProof::Agg(_) => true,
        }
    }

    pub(crate) fn intern(&self) -> &PlonkyProofIntern {
        match self {
            AggregatableProof::Txn(info) => &info.intern,
            AggregatableProof::Agg(info) => &info.intern,
        }
    }
}

impl From<GeneratedTxnProof> for AggregatableProof {
    fn from(v: GeneratedTxnProof) -> Self {
        Self::Txn(v)
    }
}

impl From<GeneratedAggProof> for AggregatableProof {
    fn from(v: GeneratedAggProof) -> Self {
        Self::Agg(v)
    }
}
