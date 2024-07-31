use ethereum_types::{Address, H256, U256};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use starky::batch_proof::BatchStarkProof;
use starky::config::StarkConfig;
use starky::lookup::GrandProductChallengeSet;
use starky::proof::{MultiProof, StarkProofChallenges};

use crate::all_stark::NUM_TABLES;
use crate::proof::PublicValues;
use crate::util::{get_h160, get_h256, get_u256, h2u};
use crate::witness::state::RegistersState;

/// A batched STARK proof for all tables, plus some metadata used to create
/// recursive wrapper proof.
#[derive(Debug, Clone)]
pub struct EvmProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// A multi-proof containing all proofs for the different STARK modules and
    /// their cross-table lookup challenges.
    pub batch_proof: BatchStarkProof<F, C, D, NUM_TABLES>,
    /// Public memory values used for the recursive proofs.
    pub public_values: PublicValues,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> EvmProof<F, C, D> {
    /// Returns the degree of the batched STARK proof.
    pub fn degree_bits(&self, config: &StarkConfig) -> usize {
        self.batch_proof.recover_degree_bits(config)
    }
}

/// Randomness for all STARKs.
pub(crate) struct EvmProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    /// Randomness used in the batched STARK proof.
    pub stark_challenges: StarkProofChallenges<F, D>,
    /// Randomness used for cross-table lookups.
    pub ctl_challenges: GrandProductChallengeSet<F>,
}
