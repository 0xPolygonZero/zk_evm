use ethereum_types::{Address, H256, U256};
use plonky2::field::extension::Extendable;
use plonky2::fri::proof::FriProof;
use plonky2::hash::hash_types::{HashOutTarget, MerkleCapTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::iop::challenger::Challenger;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use serde::{Deserialize, Serialize};
use starky::batch_proof::BatchStarkProof;
use starky::config::StarkConfig;
use starky::lookup::{get_grand_product_challenge_set, GrandProductChallengeSet};
use starky::proof::{MultiProof, StarkProofChallenges};

use crate::all_stark::NUM_TABLES;
use crate::get_challenges::observe_public_values;
use crate::proof::PublicValues;
use crate::util::{get_h160, get_h256, get_u256, h2u};
use crate::witness::errors::ProgramError;
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

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> EvmProof<F, C, D> {
    /// Computes all Fiat-Shamir challenges used in the STARK proof.
    pub(crate) fn get_challenges(
        &self,
        config: &StarkConfig,
    ) -> Result<StarkProofChallenges<F, D>, anyhow::Error> {
        let mut challenger = Challenger::<F, C::Hasher>::new();

        challenger.observe_cap(&self.batch_proof.trace_cap);
        observe_public_values::<F, C, D>(&mut challenger, &self.public_values)
            .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, config.num_challenges);

        challenger.observe_cap(
            &self
                .batch_proof
                .auxiliary_polys_cap
                .as_ref()
                .expect("No auxiliary cap?"),
        );
        let stark_alphas = challenger.get_n_challenges(config.num_challenges);

        challenger.observe_cap(
            &self
                .batch_proof
                .quotient_polys_cap
                .as_ref()
                .expect("No quotient cap?"),
        );
        let stark_zeta = challenger.get_extension_challenge::<D>();

        for opening in &self.batch_proof.openings {
            challenger.observe_openings(&opening.to_fri_openings());
        }

        let FriProof {
            commit_phase_merkle_caps,
            final_poly,
            pow_witness,
            ..
        } = &self.batch_proof.opening_proof;
        let degree_bits = self.degree_bits(config);

        let fri_challenges = challenger.fri_challenges::<C, D>(
            commit_phase_merkle_caps,
            final_poly,
            *pow_witness,
            degree_bits,
            &config.fri_config,
        );

        Ok(StarkProofChallenges {
            lookup_challenge_set: Some(ctl_challenges), // CTL challenge contains lookup challenges.
            stark_alphas,
            stark_zeta,
            fri_challenges,
        })
    }
}
