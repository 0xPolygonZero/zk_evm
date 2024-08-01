use anyhow::{ensure, Result};
use ethereum_types::{BigEndianHash, U256};
use hashbrown::HashMap;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use starky::batch_proof::BatchStarkProofWithPublicInputs;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{get_ctl_vars_from_proofs, verify_cross_table_lookups};
use starky::lookup::{get_grand_product_challenge_set, GrandProductChallenge};
use starky::stark::Stark;
use starky::verifier::verify_stark_proof_with_challenges;

use crate::all_stark::{AllStark, Table, NUM_TABLES};
use crate::batch_proof::EvmProof;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::get_challenges::observe_public_values;
use crate::memory::segments::Segment;
use crate::memory::VALUE_LIMBS;
use crate::proof::{AllProof, AllProofChallenges, MemCap, PublicValues};
use crate::util::h2u;

fn verify_evm_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
    const N: usize,
>(
    all_stark: &AllStark<F, D>,
    evm_proof: EvmProof<F, C, D>,
    config: &StarkConfig,
    is_initial: bool,
) -> Result<()> {
    let mut challenger = Challenger::<F, C::Hasher>::new();

    // TODO: Can we observe public values first, so that we can use
    // `batch_proof_with_pis.get_challenges`?
    challenger.observe_cap(&evm_proof.batch_proof.trace_cap);
    observe_public_values::<F, C, D>(&mut challenger, &evm_proof.public_values)
        .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

    let ctl_challenges = get_grand_product_challenge_set(&mut challenger, config.num_challenges);

    let lookup_challenges = ctl_challenges
        .challenges
        .iter()
        .map(|ch| ch.beta)
        .collect::<Vec<_>>();

    challenger.observe_cap(
        &evm_proof
            .batch_proof
            .auxiliary_polys_cap
            .expect("No auxiliary cap?"),
    );

    let alphas = challenger.get_n_challenges(config.num_challenges);
    challenger.observe_cap(
        &evm_proof
            .batch_proof
            .quotient_polys_cap
            .expect("No quotient cap?"),
    );

    let zeta = challenger.get_extension_challenge::<D>();

    for opening in evm_proof.batch_proof.openings {
        challenger.observe_openings(&opening.to_fri_openings());
    }

    let fri_alpha = challenger.get_extension_challenge::<D>();
    Ok(())
}
