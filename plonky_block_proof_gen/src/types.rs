use std::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    ops::{Range, RangeInclusive},
};

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use serde::{Deserialize, Serialize};

pub type BlockHeight = u64;

pub type TxnIdx = usize;

pub type PlonkyProofIntern = ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>;

pub type AllRecursiveCircuits = plonky2_evm::fixed_recursive_verifier::AllRecursiveCircuits<
    GoldilocksField,
    PoseidonGoldilocksConfig,
    2,
>;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ProofUnderlyingTxns {
    pub txn_idxs: Range<TxnIdx>,
}

impl Display for ProofUnderlyingTxns {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.num_txns() {
            0 => write!(f, "EMPTY_TXN"),
            _ => write!(f, "{}-{}", self.txn_idxs.start, self.txn_idxs.end - 1),
        }
    }
}

impl ProofUnderlyingTxns {
    pub fn combine(&self, other: &Self) -> ProofUnderlyingTxns {
        let combined_range = (self.txn_idxs.start.min(other.txn_idxs.start))
            ..(self.txn_idxs.end.max(other.txn_idxs.end));

        combined_range.into()
    }

    pub fn num_txns(&self) -> usize {
        self.txn_idxs.end - self.txn_idxs.start
    }

    pub fn contains_all_txns_in_block(&self, num_txns_in_block: usize) -> bool {
        self.num_txns() == num_txns_in_block
    }
}

impl From<Range<TxnIdx>> for ProofUnderlyingTxns {
    fn from(txn_idxs: Range<TxnIdx>) -> Self {
        Self { txn_idxs }
    }
}

impl From<RangeInclusive<TxnIdx>> for ProofUnderlyingTxns {
    fn from(txn_idxs: RangeInclusive<TxnIdx>) -> Self {
        Self {
            txn_idxs: Range {
                start: *txn_idxs.start(),
                end: *txn_idxs.end() + 1,
            },
        }
    }
}

impl From<ProofUnderlyingTxns> for Range<TxnIdx> {
    fn from(underlying_txns: ProofUnderlyingTxns) -> Self {
        underlying_txns.txn_idxs
    }
}

impl Ord for ProofUnderlyingTxns {
    /// Compare two txn ranges.
    ///
    /// Assumes that empty txns (eg. `1..1`) will never be compared.
    fn cmp(&self, other: &Self) -> Ordering {
        match self == other {
            true => Ordering::Equal,
            false => match (self.txn_idxs.end - 1).cmp(&other.txn_idxs.start) {
                Ordering::Less => Ordering::Less,
                Ordering::Greater => Ordering::Greater,
                Ordering::Equal => match self.txn_idxs.start.cmp(&(other.txn_idxs.end - 1)) {
                    Ordering::Less => Ordering::Greater,
                    Ordering::Equal => Ordering::Equal,
                    Ordering::Greater => Ordering::Less,
                },
            },
        }
    }
}

impl PartialOrd for ProofUnderlyingTxns {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
