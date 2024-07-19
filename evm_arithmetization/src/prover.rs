use std::any::type_name;
use std::iter::once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, ensure, Result};
use itertools::Itertools;
use once_cell::sync::Lazy;
use plonky2::batch_fri::oracle::BatchFriOracle;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::packable::Packable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::Field;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::structure::{FriInstanceInfo, FriOpeningBatch, FriOracleInfo};
use plonky2::fri::FriConfig;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_maybe_rayon::*;
use serde::{Deserialize, Serialize};
use starky::batch_proof::{BatchStarkProof, BatchStarkProofWithPublicInputs};
use starky::config::StarkConfig;
use starky::cross_table_lookup::{get_ctl_auxiliary_polys, get_ctl_data, CtlData};
use starky::lookup::{lookup_helper_columns, GrandProductChallengeSet};
use starky::proof::{
    MultiProof, StarkOpeningSet, StarkProof, StarkProofWithMetadata, StarkProofWithPublicInputs,
};
use starky::prover::{compute_quotient_polys, prove_with_commitment};
use starky::stark::Stark;

use crate::all_stark::{all_cross_table_lookups, AllStark, Table, NUM_TABLES};
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
use crate::byte_packing::byte_packing_stark::BytePackingStark;
use crate::cpu::cpu_stark::CpuStark;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::{set_registers_and_run, ExtraSegmentData, Interpreter};
use crate::generation::state::{GenerationState, State};
use crate::generation::{generate_traces, GenerationInputs};
use crate::get_challenges::observe_public_values;
use crate::keccak::keccak_stark::KeccakStark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::logic::LogicStark;
use crate::memory::memory_stark::MemoryStark;
use crate::memory::segments::Segment;
use crate::memory_continuation::memory_continuation_stark::MemoryContinuationStark;
use crate::proof::{AllProof, MemCap, PublicValues, RegistersData};
use crate::witness::memory::{MemoryAddress, MemoryState};
use crate::witness::state::RegistersState;

/// Structure holding the data needed to initialize a segment.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct GenerationSegmentData {
    /// Indicates whether this corresponds to a dummy segment.
    pub(crate) is_dummy: bool,
    /// Indicates the position of this segment in a sequence of
    /// executions for a larger payload.
    pub(crate) segment_index: usize,
    /// Registers at the start of the segment execution.
    pub(crate) registers_before: RegistersState,
    /// Registers at the end of the segment execution.
    pub(crate) registers_after: RegistersState,
    /// Memory at the start of the segment execution.
    pub(crate) memory: MemoryState,
    /// Extra data required to initialize a segment.
    pub(crate) extra_data: ExtraSegmentData,
    /// Log of the maximal cpu length.
    pub(crate) max_cpu_len_log: Option<usize>,
}

impl GenerationSegmentData {
    /// Indicates if this segment is a dummy one.
    pub fn is_dummy(&self) -> bool {
        self.is_dummy
    }

    /// Retrieves the index of this segment.
    pub fn segment_index(&self) -> usize {
        self.segment_index
    }
}

pub fn zkevm_fast_config() -> StarkConfig {
    let cap_height = 4;
    let mut strategy = Vec::new();
    for window in Table::all_degree_logs().windows(2) {
        if window[0] != window[1] {
            strategy.push(window[1] - window[0]);
        }
    }
    let mut last_degree = Table::all_degree_logs()[NUM_TABLES - 1];
    while last_degree > cap_height {
        if last_degree >= cap_height + 4 {
            strategy.push(4);
            last_degree -= 4;
        } else {
            strategy.push(last_degree - cap_height);
            last_degree = cap_height;
        }
    }

    StarkConfig {
        security_bits: 100,
        num_challenges: 2,
        fri_config: FriConfig {
            rate_bits: 1,
            cap_height,
            proof_of_work_bits: 16,
            // This strategy allows us to hit all intermediary STARK leaves while going through the
            // batched Field Merkle Trees.
            reduction_strategy: FriReductionStrategy::Fixed(strategy),
            num_query_rounds: 84,
        },
    }
}

/// Generate traces, then create all STARK proofs.
pub fn prove<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    inputs: GenerationInputs,
    segment_data: &mut GenerationSegmentData,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<AllProof<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    timed!(timing, "build kernel", Lazy::force(&KERNEL));

    let (traces, mut public_values) = timed!(
        timing,
        "generate all traces",
        generate_traces(all_stark, &inputs, config, segment_data, timing)?
    );

    check_abort_signal(abort_signal.clone())?;

    let proof = prove_with_traces(
        all_stark,
        config,
        traces,
        &mut public_values,
        timing,
        abort_signal,
    )?;

    Ok(proof)
}

/// Generate traces, then create all STARK proofs.
pub fn prove_batch<F, P, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    inputs: GenerationInputs,
    segment_data: &mut GenerationSegmentData,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<BatchStarkProofWithPublicInputs<F, C, D, 9>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    P: PackedField<Scalar = F>,
{
    timed!(timing, "build kernel", Lazy::force(&KERNEL));

    let (traces, mut public_values) = timed!(
        timing,
        "generate all traces",
        generate_traces(all_stark, &inputs, config, segment_data, timing)?
    );

    check_abort_signal(abort_signal.clone())?;

    let proof = prove_with_traces_batch::<F, P, C, D>(
        all_stark,
        config,
        traces,
        public_values,
        timing,
        abort_signal,
    )?;

    Ok(proof)
}

/// Compute all STARK proofs.
pub(crate) fn prove_with_traces<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    public_values: &mut PublicValues,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<AllProof<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    // For each STARK, we compute the polynomial commitments for the polynomials
    // interpolating its trace.
    let trace_commitments = timed!(
        timing,
        "compute all trace commitments",
        trace_poly_values
            .iter()
            .zip_eq(Table::all())
            .map(|(trace, table)| {
                timed!(
                    timing,
                    &format!("compute trace commitment for {:?}", table),
                    PolynomialBatch::<F, C, D>::from_values(
                        trace.clone(),
                        rate_bits,
                        false,
                        cap_height,
                        timing,
                        None,
                    )
                )
            })
            .collect::<Vec<_>>()
    );

    // Get the Merkle caps for all trace commitments and observe them.
    let trace_caps = trace_commitments
        .iter()
        .map(|c| c.merkle_tree.cap.clone())
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, C::Hasher>::new();
    for cap in &trace_caps {
        challenger.observe_cap(cap);
    }

    observe_public_values::<F, C, D>(&mut challenger, public_values)
        .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

    // For each STARK, compute its cross-table lookup Z polynomials and get the
    // associated `CtlData`.
    let (ctl_challenges, ctl_data_per_table) = timed!(
        timing,
        "compute CTL data",
        get_ctl_data::<F, C, D, NUM_TABLES>(
            config,
            &trace_poly_values,
            &all_stark.cross_table_lookups,
            &mut challenger,
            all_stark.arithmetic_stark.constraint_degree()
        )
    );

    let (stark_proofs, mem_before_cap, mem_after_cap) = timed!(
        timing,
        "compute all proofs given commitments",
        prove_with_commitments(
            all_stark,
            config,
            &trace_poly_values,
            trace_commitments,
            ctl_data_per_table,
            &mut challenger,
            &ctl_challenges,
            timing,
            abort_signal,
        )?
    );
    public_values.mem_before = MemCap {
        mem_cap: mem_before_cap
            .0
            .iter()
            .map(|h| {
                h.to_vec()
                    .iter()
                    .map(|hi| hi.to_canonical_u64().into())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>(),
    };
    public_values.mem_after = MemCap {
        mem_cap: mem_after_cap
            .0
            .iter()
            .map(|h| {
                h.to_vec()
                    .iter()
                    .map(|hi| hi.to_canonical_u64().into())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>(),
    };

    // This is an expensive check, hence is only run when `debug_assertions` are
    // enabled.
    #[cfg(debug_assertions)]
    {
        use hashbrown::HashMap;
        use starky::cross_table_lookup::debug_utils::check_ctls;

        use crate::verifier::debug_utils::get_memory_extra_looking_values;

        let mut extra_values = HashMap::new();
        extra_values.insert(
            *Table::Memory,
            get_memory_extra_looking_values(public_values),
        );
        check_ctls(
            &trace_poly_values,
            &all_stark.cross_table_lookups,
            &extra_values,
        );
    }

    Ok(AllProof {
        multi_proof: MultiProof {
            stark_proofs,
            ctl_challenges,
        },
        public_values: public_values.clone(),
    })
}

type ProofWithMemCaps<F, C, H, const D: usize> = (
    [StarkProofWithMetadata<F, C, D>; NUM_TABLES],
    MerkleCap<F, H>,
    MerkleCap<F, H>,
);

/// Compute all STARK proofs. STARK-batching version.
pub(crate) fn prove_with_traces_batch<F, P, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    public_values: PublicValues,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<BatchStarkProofWithPublicInputs<F, C, D, NUM_TABLES>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar = F>,
    C: GenericConfig<D, F = F>,
{
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    let trace_poly_values_sorted: [_; NUM_TABLES] = Table::all_sorted()
        .iter()
        .map(|&table| trace_poly_values[*table].clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // We compute the Field Merkle Tree of all STARK traces.
    let trace_polys_values_sorted_flat: Vec<_> = trace_poly_values_sorted
        .clone()
        .into_iter()
        .flatten()
        .collect();
    let num_trace_polys = trace_polys_values_sorted_flat.len();
    let trace_commitment = timed!(
        timing,
        "compute trace commitments",
        BatchFriOracle::<F, C, D>::from_values(
            trace_polys_values_sorted_flat,
            rate_bits,
            false,
            cap_height,
            timing,
            &vec![None; num_trace_polys],
        )
    );

    let mut challenger = Challenger::<F, C::Hasher>::new();
    challenger.observe_cap(&trace_commitment.batch_merkle_tree.cap);

    observe_public_values::<F, C, D>(&mut challenger, &public_values)
        .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

    // For each STARK, compute its cross-table lookup Z polynomials and get the
    // associated `CtlData`.
    let (ctl_challenges, ctl_data_per_table) = timed!(
        timing,
        "compute CTL data",
        get_ctl_data::<F, C, D, NUM_TABLES>(
            config,
            &trace_poly_values,
            &all_stark.cross_table_lookups,
            &mut challenger,
            all_stark.arithmetic_stark.constraint_degree()
        )
    );

    check_abort_signal(abort_signal)?;
    let lookup_challenges = ctl_challenges
        .challenges
        .iter()
        .map(|ch| ch.beta)
        .collect::<Vec<_>>();

    let auxiliary_columns = all_auxiliary_columns::<F, C, D>(
        all_stark,
        config,
        &trace_poly_values,
        &ctl_data_per_table,
        &ctl_challenges,
    );

    // We compute the Field Merkle Tree of all auxiliary columns.
    let auxiliary_columns_sorted: Vec<_> = Table::all_sorted()
        .iter()
        .map(|&table| auxiliary_columns[*table].clone())
        .collect();
    let auxiliary_columns_sorted_flat: Vec<_> = auxiliary_columns_sorted
        .clone()
        .into_iter()
        .flatten()
        .collect();
    let num_aux_polys = auxiliary_columns_sorted_flat.len();
    let auxiliary_commitment = timed!(
        timing,
        "compute auxiliary commitments",
        BatchFriOracle::<F, C, D>::from_values(
            auxiliary_columns_sorted_flat,
            rate_bits,
            false,
            cap_height,
            timing,
            &vec![None; num_aux_polys],
        )
    );
    challenger.observe_cap(&auxiliary_commitment.batch_merkle_tree.cap);

    // Quotient polynomials. They are already chunked in `degree` pieces.
    let alphas = challenger.get_n_challenges(config.num_challenges);
    let quotient_polys = all_quotient_polys::<F, P, C, D>(
        all_stark,
        &trace_poly_values_sorted,
        &trace_commitment,
        &auxiliary_columns_sorted,
        &auxiliary_commitment,
        &auxiliary_columns,
        None,
        &ctl_data_per_table,
        alphas.clone(),
        config,
    );

    // We compute the Field Merkle Tree of all quotient polynomials.
    let quotient_polys_sorted: Vec<_> = Table::all_sorted()
        .iter()
        .map(|&table| quotient_polys[*table].clone())
        .collect();
    let quotient_polys_sorted_flat: Vec<_> = quotient_polys_sorted
        .clone()
        .into_iter()
        .flatten()
        .collect();
    let num_quotient_polys = quotient_polys_sorted_flat.len();
    let quotient_commitment = timed!(
        timing,
        "compute quotient commitments",
        BatchFriOracle::<F, C, D>::from_coeffs(
            quotient_polys_sorted_flat,
            rate_bits,
            false,
            cap_height,
            timing,
            &vec![None; num_quotient_polys],
        )
    );
    challenger.observe_cap(&quotient_commitment.batch_merkle_tree.cap);

    let zeta = challenger.get_extension_challenge::<D>();

    // To avoid leaking witness data, we want to ensure that our opening locations,
    // `zeta` and `g * zeta`, are not in our subgroup `H`. It suffices to check
    // `zeta` only, since `(g * zeta)^n = zeta^n`, where `n` is the order of
    // `g`.
    let degree_bits = trace_commitment.degree_bits[0];
    let g = F::primitive_root_of_unity(degree_bits);
    ensure!(
        zeta.exp_power_of_2(degree_bits) != F::Extension::ONE,
        "Opening point is in the subgroup."
    );

    let all_fri_instances = all_fri_instance_info::<F, C, D>(
        all_stark,
        zeta,
        &trace_poly_values_sorted,
        &auxiliary_columns_sorted,
        &quotient_polys_sorted,
        &ctl_data_per_table,
        config,
    );

    // Get the FRI openings and observe them.
    // Compute all openings: evaluate all committed polynomials at `zeta` and, when
    // necessary, at `g * zeta`.
    let openings = all_openings(
        all_stark,
        &trace_poly_values_sorted,
        &trace_commitment,
        &auxiliary_columns_sorted,
        &auxiliary_commitment,
        &quotient_polys_sorted,
        &quotient_commitment,
        &ctl_data_per_table,
        zeta,
        config,
    );

    for opening in openings.iter() {
        challenger.observe_openings(&opening.to_fri_openings());
    }

    let initial_merkle_trees = [
        &trace_commitment,
        &auxiliary_commitment,
        &quotient_commitment,
    ];

    let mut degree_bits_squashed = Table::all_degree_logs().to_vec();
    degree_bits_squashed.dedup();
    let opening_proof = BatchFriOracle::prove_openings(
        &degree_bits_squashed,
        &all_fri_instances,
        &initial_merkle_trees,
        &mut challenger,
        &config.fri_params(degree_bits),
        timing,
    );

    // This is an expensive check, hence is only run when `debug_assertions` are
    // enabled.
    #[cfg(debug_assertions)]
    {
        use hashbrown::HashMap;
        use starky::cross_table_lookup::debug_utils::check_ctls;

        use crate::verifier::debug_utils::get_memory_extra_looking_values;

        let mut extra_values = HashMap::new();
        extra_values.insert(
            *Table::Memory,
            get_memory_extra_looking_values(&public_values),
        );
        check_ctls(
            &trace_poly_values_sorted,
            &all_stark.cross_table_lookups,
            &extra_values,
        );
    }

    let stark_proof = BatchStarkProof {
        trace_cap: trace_commitment.batch_merkle_tree.cap.clone(),
        auxiliary_polys_cap: Some(auxiliary_commitment.batch_merkle_tree.cap),
        quotient_polys_cap: Some(quotient_commitment.batch_merkle_tree.cap),
        openings: openings.try_into().unwrap(),
        opening_proof,
    };

    Ok(BatchStarkProofWithPublicInputs {
        proof: stark_proof,
        public_inputs: vec![],
    })
}

/// Generates all auxiliary columns.
fn all_auxiliary_columns<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    ctl_challenges: &GrandProductChallengeSet<F>,
) -> Vec<Vec<PolynomialValues<F>>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let mut res = Vec::new();

    // Arithmetic.
    res.push(auxiliary_columns_single_stark::<
        F,
        C,
        ArithmeticStark<F, D>,
        D,
    >(
        all_stark.arithmetic_stark,
        config,
        &trace_poly_values[*Table::Arithmetic],
        &ctl_data_per_table[*Table::Arithmetic],
        ctl_challenges,
    ));

    // BytePacking.
    res.push(auxiliary_columns_single_stark::<
        F,
        C,
        BytePackingStark<F, D>,
        D,
    >(
        all_stark.byte_packing_stark,
        config,
        &trace_poly_values[*Table::BytePacking],
        &ctl_data_per_table[*Table::BytePacking],
        ctl_challenges,
    ));

    // Cpu.
    res.push(auxiliary_columns_single_stark::<F, C, CpuStark<F, D>, D>(
        all_stark.cpu_stark,
        config,
        &trace_poly_values[*Table::Cpu],
        &ctl_data_per_table[*Table::Cpu],
        ctl_challenges,
    ));

    // Keccak.
    res.push(
        auxiliary_columns_single_stark::<F, C, KeccakStark<F, D>, D>(
            all_stark.keccak_stark,
            config,
            &trace_poly_values[*Table::Keccak],
            &ctl_data_per_table[*Table::Keccak],
            ctl_challenges,
        ),
    );

    // KeccakSponge.
    res.push(auxiliary_columns_single_stark::<
        F,
        C,
        KeccakSpongeStark<F, D>,
        D,
    >(
        all_stark.keccak_sponge_stark,
        config,
        &trace_poly_values[*Table::KeccakSponge],
        &ctl_data_per_table[*Table::KeccakSponge],
        ctl_challenges,
    ));

    // Logic.
    res.push(auxiliary_columns_single_stark::<F, C, LogicStark<F, D>, D>(
        all_stark.logic_stark,
        config,
        &trace_poly_values[*Table::Logic],
        &ctl_data_per_table[*Table::Logic],
        ctl_challenges,
    ));

    // Memory.
    res.push(
        auxiliary_columns_single_stark::<F, C, MemoryStark<F, D>, D>(
            all_stark.memory_stark,
            config,
            &trace_poly_values[*Table::Memory],
            &ctl_data_per_table[*Table::Memory],
            ctl_challenges,
        ),
    );

    // MemBefore.
    res.push(auxiliary_columns_single_stark::<
        F,
        C,
        MemoryContinuationStark<F, D>,
        D,
    >(
        all_stark.mem_before_stark,
        config,
        &trace_poly_values[*Table::MemBefore],
        &ctl_data_per_table[*Table::MemBefore],
        ctl_challenges,
    ));

    // MemAfter.
    res.push(auxiliary_columns_single_stark::<
        F,
        C,
        MemoryContinuationStark<F, D>,
        D,
    >(
        all_stark.mem_before_stark,
        config,
        &trace_poly_values[*Table::MemAfter],
        &ctl_data_per_table[*Table::MemAfter],
        ctl_challenges,
    ));

    res
}

fn auxiliary_columns_single_stark<F, C, S, const D: usize>(
    stark: S,
    config: &StarkConfig,
    trace_poly_values: &[PolynomialValues<F>],
    ctl_data: &CtlData<F>,
    ctl_challenges: &GrandProductChallengeSet<F>,
) -> Vec<PolynomialValues<F>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let rate_bits = config.fri_config.rate_bits;
    let constraint_degree = stark.constraint_degree();
    assert!(
        constraint_degree <= (1 << rate_bits) + 1,
        "The degree of the Stark constraints must be <= blowup_factor + 1"
    );

    let lookup_challenges: Vec<_> = ctl_challenges.challenges.iter().map(|ch| ch.beta).collect();
    // Add lookup columns.
    let lookups = stark.lookups();
    let mut res = {
        let mut columns = Vec::new();
        for lookup in &lookups {
            for &challenge in lookup_challenges.iter() {
                columns.extend(lookup_helper_columns(
                    lookup,
                    trace_poly_values,
                    challenge,
                    constraint_degree,
                ));
            }
        }
        columns
    };
    let num_lookup_columns = res.len();

    // Add CTL columns.
    if let Some(p) = get_ctl_auxiliary_polys(Some(ctl_data)) {
        res.extend(p);
    }

    debug_assert!(
        (stark.uses_lookups() || stark.requires_ctls()) || get_ctl_auxiliary_polys(Some(ctl_data)).is_none(),
        "There should be auxiliary polynomials if and only if we have either lookups or require cross-table lookups."
    );

    res
}

fn quotient_polys_single_stark<F, P, C, S, const D: usize>(
    table: Table,
    stark: &S,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitment: &BatchFriOracle<F, C, D>,
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    auxiliary_commitment: &BatchFriOracle<F, C, D>,
    all_auxiliary_columns: &Vec<Vec<PolynomialValues<F>>>,
    lookup_challenges: Option<&Vec<F>>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    alphas: Vec<F>,
    config: &StarkConfig,
) -> Vec<PolynomialCoeffs<F>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar = F>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let degree_bits = Table::all_degree_logs()[Table::table_to_sorted_index()[*table]];
    let (index_outer, index_inner) =
        Table::sorted_index_pair()[Table::table_to_sorted_index()[*table]];
    let mut num_trace_polys_before = 0;
    let mut num_aux_polys_before = 0;
    for i in 0..index_inner {
        let prev_sorted_table = Table::table_to_sorted_index()[*table] - i - 1;
        num_trace_polys_before += trace_poly_values_sorted[prev_sorted_table].len();
        num_aux_polys_before += auxiliary_columns_sorted[prev_sorted_table].len();
    }
    let trace_leave_len = trace_poly_values_sorted[Table::table_to_sorted_index()[*table]].len();
    let get_trace_packed = |index, step| {
        trace_commitment.get_lde_values_packed::<P>(
            index_outer,
            index,
            step,
            num_trace_polys_before,
            trace_leave_len,
        )
    };
    let aux_leave_len = auxiliary_columns_sorted[Table::table_to_sorted_index()[*table]].len();
    let get_aux_packed = |index, step| {
        auxiliary_commitment.get_lde_values_packed(
            index_outer,
            index,
            step,
            num_aux_polys_before,
            aux_leave_len,
        )
    };

    let quotient_polys = compute_quotient_polys::<F, P, C, _, D>(
        stark,
        &get_trace_packed,
        &get_aux_packed,
        lookup_challenges,
        Some(&ctl_data_per_table[*table]),
        &vec![],
        alphas,
        degree_bits,
        stark.num_lookup_helper_columns(config),
        config,
    )
    .expect("Couldn't compute quotient polys.");

    // Chunk the quotient polynomials.
    let degree = 1 << degree_bits;
    quotient_polys
        .into_par_iter()
        .flat_map(|mut quotient_poly| {
            quotient_poly
                .trim_to_len(degree * stark.quotient_degree_factor())
                .expect("Quotient has failed, the vanishing polynomial is not divisible by Z_H");
            // Split quotient into degree-n chunks.
            quotient_poly.chunks(degree)
        })
        .collect()
}

/// Generates all quotient polynomials.
fn all_quotient_polys<F, P, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitment: &BatchFriOracle<F, C, D>,
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    auxiliary_commitment: &BatchFriOracle<F, C, D>,
    all_auxiliary_columns: &Vec<Vec<PolynomialValues<F>>>,
    lookup_challenges: Option<&Vec<F>>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    alphas: Vec<F>,
    config: &StarkConfig,
) -> Vec<Vec<PolynomialCoeffs<F>>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar = F>,
    C: GenericConfig<D, F = F>,
{
    let mut res = Vec::new();

    // Arithmetic.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::Arithmetic,
        &all_stark.arithmetic_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // Bytepacking.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::BytePacking,
        &all_stark.byte_packing_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // Cpu.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::Cpu,
        &all_stark.cpu_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // Keccak.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::Keccak,
        &all_stark.keccak_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // KeccakSponge.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::KeccakSponge,
        &all_stark.keccak_sponge_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // Logic.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::Logic,
        &all_stark.logic_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));
    // Memory.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::Memory,
        &all_stark.memory_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // MemBefore.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::MemBefore,
        &all_stark.mem_before_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    // MemAfter.
    res.push(quotient_polys_single_stark::<F, P, C, _, D>(
        Table::MemAfter,
        &all_stark.mem_after_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        all_auxiliary_columns,
        lookup_challenges,
        ctl_data_per_table,
        alphas.clone(),
        config,
    ));

    res
}

/// Generates all FRI instances. They are sorted by decreasing degree.
fn fri_instance_info_single_stark<F, C, S, const D: usize>(
    table: Table,
    stark: &S,
    zeta: F::Extension,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    quotient_polys_sorted: &Vec<Vec<PolynomialCoeffs<F>>>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    config: &StarkConfig,
) -> FriInstanceInfo<F, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let g = F::primitive_root_of_unity(
        Table::all_degree_logs()[Table::table_to_sorted_index()[*table]],
    );
    let sorted_index = Table::table_to_sorted_index()[*table];
    let num_ctl_helper_polys = ctl_data_per_table[*table].num_ctl_helper_polys();
    let mut num_trace_polys_before = 0;
    let mut num_aux_polys_before = 0;
    let mut num_quotient_polys_before = 0;
    for i in 0..sorted_index {
        let prev_sorted_table = Table::table_to_sorted_index()[*table] - i - 1;
        num_trace_polys_before += trace_poly_values_sorted[i].len();
        num_aux_polys_before += auxiliary_columns_sorted[i].len();
        num_quotient_polys_before += quotient_polys_sorted[i].len();
    }
    let num_aux_columns = auxiliary_columns_sorted[sorted_index].len();
    let num_quotient_polys = quotient_polys_sorted[sorted_index].len();
    let num_cols_before_ctlzs = num_aux_polys_before
        + stark.num_lookup_helper_columns(config)
        + ctl_data_per_table[*table]
            .num_ctl_helper_polys()
            .iter()
            .sum::<usize>();

    stark.fri_instance_batch(
        zeta,
        g,
        num_trace_polys_before,
        num_aux_polys_before,
        num_aux_columns,
        num_quotient_polys_before,
        num_quotient_polys,
        num_cols_before_ctlzs,
    )
}

/// Generates all FRI instances. They are sorted by decreasing degree.
fn all_fri_instance_info<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    zeta: F::Extension,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    quotient_polys_sorted: &Vec<Vec<PolynomialCoeffs<F>>>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    config: &StarkConfig,
) -> Vec<FriInstanceInfo<F, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let mut res = Vec::new();

    // Arithmetic.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::Arithmetic,
        &all_stark.arithmetic_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // BytePacking.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::BytePacking,
        &all_stark.byte_packing_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // Cpu.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::Cpu,
        &all_stark.cpu_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // Keccak.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::Keccak,
        &all_stark.keccak_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // KeccakSponge.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::KeccakSponge,
        &all_stark.keccak_sponge_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // Logic.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::Logic,
        &all_stark.logic_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // Memory.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::Memory,
        &all_stark.memory_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // MemBefore.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::MemBefore,
        &all_stark.mem_before_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    // MemAfter.
    res.push(fri_instance_info_single_stark::<F, C, _, D>(
        Table::MemAfter,
        &all_stark.mem_after_stark,
        zeta,
        trace_poly_values_sorted,
        auxiliary_columns_sorted,
        quotient_polys_sorted,
        ctl_data_per_table,
        config,
    ));

    let res_sorted: Vec<_> = Table::all_sorted()
        .iter()
        .map(|&table| res[*table].clone())
        .collect();

    let mut squashed_res = Vec::new();
    let mut i = 0;
    let mut current_instance = FriInstanceInfo {
        oracles: vec![
            FriOracleInfo {
                num_polys: 0,
                blinding: false,
            },
            FriOracleInfo {
                num_polys: 0,
                blinding: false,
            },
            FriOracleInfo {
                num_polys: 0,
                blinding: false,
            },
        ],
        batches: vec![],
    };

    while i < NUM_TABLES {
        let instance = &res_sorted[i];
        for (k, oracle) in instance.oracles.iter().enumerate() {
            current_instance.oracles[k].num_polys += oracle.num_polys;
        }
        current_instance.batches.extend(instance.batches.clone());

        if i == NUM_TABLES - 1 || Table::all_degree_logs()[i + 1] < Table::all_degree_logs()[i] {
            squashed_res.push(current_instance.clone());
            current_instance.oracles = vec![
                FriOracleInfo {
                    num_polys: 0,
                    blinding: false,
                },
                FriOracleInfo {
                    num_polys: 0,
                    blinding: false,
                },
                FriOracleInfo {
                    num_polys: 0,
                    blinding: false,
                },
            ];
            current_instance.batches = vec![];
        }
        i += 1;
    }

    squashed_res
}

fn all_openings_single_stark<F, C, S, const D: usize>(
    table: Table,
    stark: &S,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitment: &BatchFriOracle<F, C, D>,
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    auxiliary_commitment: &BatchFriOracle<F, C, D>,
    quotient_polys_sorted: &Vec<Vec<PolynomialCoeffs<F>>>,
    quotient_commitment: &BatchFriOracle<F, C, D>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    zeta: F::Extension,
    config: &StarkConfig,
) -> StarkOpeningSet<F, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let g = F::primitive_root_of_unity(
        Table::all_degree_logs()[Table::table_to_sorted_index()[*table]],
    );
    let table_sorted_index = Table::table_to_sorted_index()[*table];
    let (_, index_inner) = Table::sorted_index_pair()[table_sorted_index];
    let mut num_trace_polys_before = 0;
    let mut num_aux_polys_before = 0;
    let mut num_quotient_polys_before = 0;
    for i in 0..index_inner {
        let prev_sorted_table = Table::table_to_sorted_index()[*table] - i - 1;
        num_trace_polys_before += trace_poly_values_sorted[i].len();
        num_aux_polys_before += auxiliary_columns_sorted[i].len();
        num_quotient_polys_before += quotient_polys_sorted[i].len();
    }

    StarkOpeningSet::new_from_batch(
        stark,
        zeta,
        g,
        trace_commitment,
        num_trace_polys_before
            ..(num_trace_polys_before + trace_poly_values_sorted[table_sorted_index].len()),
        auxiliary_commitment,
        num_aux_polys_before
            ..(num_aux_polys_before + auxiliary_columns_sorted[table_sorted_index].len()),
        quotient_commitment,
        num_quotient_polys_before
            ..(num_quotient_polys_before + quotient_polys_sorted[table_sorted_index].len()),
        stark.num_lookup_helper_columns(config),
        &ctl_data_per_table[*table].num_ctl_helper_polys(),
    )
}

/// Generates all opening sets.
fn all_openings<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    trace_poly_values_sorted: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitment: &BatchFriOracle<F, C, D>,
    auxiliary_columns_sorted: &Vec<Vec<PolynomialValues<F>>>,
    auxiliary_commitment: &BatchFriOracle<F, C, D>,
    quotient_polys_sorted: &Vec<Vec<PolynomialCoeffs<F>>>,
    quotient_commitment: &BatchFriOracle<F, C, D>,
    ctl_data_per_table: &[CtlData<F>; NUM_TABLES],
    zeta: F::Extension,
    config: &StarkConfig,
) -> Vec<StarkOpeningSet<F, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let degree_bits = Table::all_degree_logs();
    let mut res = Vec::new();

    // Arithmetic.
    res.push(all_openings_single_stark(
        Table::Arithmetic,
        &all_stark.arithmetic_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // Bytepacking.
    res.push(all_openings_single_stark(
        Table::BytePacking,
        &all_stark.byte_packing_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // Cpu.
    res.push(all_openings_single_stark(
        Table::Cpu,
        &all_stark.cpu_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // Keccak.
    res.push(all_openings_single_stark(
        Table::Keccak,
        &all_stark.keccak_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // KeccakSponge.
    res.push(all_openings_single_stark(
        Table::KeccakSponge,
        &all_stark.keccak_sponge_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // Logic.
    res.push(all_openings_single_stark(
        Table::Logic,
        &all_stark.logic_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // Memory.
    res.push(all_openings_single_stark(
        Table::Memory,
        &all_stark.memory_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // MemBefore.
    res.push(all_openings_single_stark(
        Table::MemBefore,
        &all_stark.mem_before_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    // MemAfter.
    res.push(all_openings_single_stark(
        Table::MemAfter,
        &all_stark.mem_after_stark,
        trace_poly_values_sorted,
        trace_commitment,
        auxiliary_columns_sorted,
        auxiliary_commitment,
        quotient_polys_sorted,
        quotient_commitment,
        ctl_data_per_table,
        zeta,
        config,
    ));

    res
}

/// Generates a proof for each STARK.
/// At this stage, we have computed the trace polynomials commitments for the
/// various STARKs, and we have the cross-table lookup data for each table,
/// including the associated challenges.
/// - `trace_poly_values` are the trace values for each STARK.
/// - `trace_commitments` are the trace polynomials commitments for each STARK.
/// - `ctl_data_per_table` group all the cross-table lookup data for each STARK.
///
/// Each STARK uses its associated data to generate a proof.
fn prove_with_commitments<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: &[Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitments: Vec<PolynomialBatch<F, C, D>>,
    ctl_data_per_table: [CtlData<F>; NUM_TABLES],
    challenger: &mut Challenger<F, C::Hasher>,
    ctl_challenges: &GrandProductChallengeSet<F>,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<ProofWithMemCaps<F, C, C::Hasher, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let (arithmetic_proof, _) = timed!(
        timing,
        "prove Arithmetic STARK",
        prove_single_table(
            &all_stark.arithmetic_stark,
            config,
            &trace_poly_values[Table::Arithmetic as usize],
            &trace_commitments[Table::Arithmetic as usize],
            &ctl_data_per_table[Table::Arithmetic as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (byte_packing_proof, _) = timed!(
        timing,
        "prove byte packing STARK",
        prove_single_table(
            &all_stark.byte_packing_stark,
            config,
            &trace_poly_values[Table::BytePacking as usize],
            &trace_commitments[Table::BytePacking as usize],
            &ctl_data_per_table[Table::BytePacking as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (cpu_proof, _) = timed!(
        timing,
        "prove CPU STARK",
        prove_single_table(
            &all_stark.cpu_stark,
            config,
            &trace_poly_values[Table::Cpu as usize],
            &trace_commitments[Table::Cpu as usize],
            &ctl_data_per_table[Table::Cpu as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (keccak_proof, _) = timed!(
        timing,
        "prove Keccak STARK",
        prove_single_table(
            &all_stark.keccak_stark,
            config,
            &trace_poly_values[Table::Keccak as usize],
            &trace_commitments[Table::Keccak as usize],
            &ctl_data_per_table[Table::Keccak as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (keccak_sponge_proof, _) = timed!(
        timing,
        "prove Keccak sponge STARK",
        prove_single_table(
            &all_stark.keccak_sponge_stark,
            config,
            &trace_poly_values[Table::KeccakSponge as usize],
            &trace_commitments[Table::KeccakSponge as usize],
            &ctl_data_per_table[Table::KeccakSponge as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (logic_proof, _) = timed!(
        timing,
        "prove logic STARK",
        prove_single_table(
            &all_stark.logic_stark,
            config,
            &trace_poly_values[Table::Logic as usize],
            &trace_commitments[Table::Logic as usize],
            &ctl_data_per_table[Table::Logic as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (memory_proof, _) = timed!(
        timing,
        "prove memory STARK",
        prove_single_table(
            &all_stark.memory_stark,
            config,
            &trace_poly_values[Table::Memory as usize],
            &trace_commitments[Table::Memory as usize],
            &ctl_data_per_table[Table::Memory as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (mem_before_proof, mem_before_cap) = timed!(
        timing,
        "prove mem_before STARK",
        prove_single_table(
            &all_stark.mem_before_stark,
            config,
            &trace_poly_values[Table::MemBefore as usize],
            &trace_commitments[Table::MemBefore as usize],
            &ctl_data_per_table[Table::MemBefore as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal.clone(),
        )?
    );
    let (mem_after_proof, mem_after_cap) = timed!(
        timing,
        "prove mem_after STARK",
        prove_single_table(
            &all_stark.mem_after_stark,
            config,
            &trace_poly_values[Table::MemAfter as usize],
            &trace_commitments[Table::MemAfter as usize],
            &ctl_data_per_table[Table::MemAfter as usize],
            ctl_challenges,
            challenger,
            timing,
            abort_signal,
        )?
    );

    Ok((
        [
            arithmetic_proof,
            byte_packing_proof,
            cpu_proof,
            keccak_proof,
            keccak_sponge_proof,
            logic_proof,
            memory_proof,
            mem_before_proof,
            mem_after_proof,
        ],
        mem_before_cap,
        mem_after_cap,
    ))
}

type ProofSingleWithCap<F, C, H, const D: usize> =
    (StarkProofWithMetadata<F, C, D>, MerkleCap<F, H>);

/// Computes a proof for a single STARK table, including:
/// - the initial state of the challenger,
/// - all the requires Merkle caps,
/// - all the required polynomial and FRI argument openings.
///
/// Returns the proof, along with the associated `MerkleCap`.
pub(crate) fn prove_single_table<F, C, S, const D: usize>(
    stark: &S,
    config: &StarkConfig,
    trace_poly_values: &[PolynomialValues<F>],
    trace_commitment: &PolynomialBatch<F, C, D>,
    ctl_data: &CtlData<F>,
    ctl_challenges: &GrandProductChallengeSet<F>,
    challenger: &mut Challenger<F, C::Hasher>,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<ProofSingleWithCap<F, C, C::Hasher, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    check_abort_signal(abort_signal.clone())?;

    // Clear buffered outputs.
    let init_challenger_state = challenger.compact();

    let proof = prove_with_commitment(
        stark,
        config,
        trace_poly_values,
        trace_commitment,
        Some(ctl_data),
        Some(ctl_challenges),
        challenger,
        &[],
        timing,
    )
    .map(|proof_with_pis| StarkProofWithMetadata {
        proof: proof_with_pis.proof,
        init_challenger_state,
    })?;

    Ok((proof, trace_commitment.merkle_tree.cap.clone()))
}

/// Utility method that checks whether a kill signal has been emitted by one of
/// the workers, which will result in an early abort for all the other processes
/// involved in the same set of transactions.
pub fn check_abort_signal(abort_signal: Option<Arc<AtomicBool>>) -> Result<()> {
    if let Some(signal) = abort_signal {
        if signal.load(Ordering::Relaxed) {
            return Err(anyhow!("Stopping job from abort signal."));
        }
    }

    Ok(())
}

/// Builds a new `GenerationSegmentData`.
/// This new segment's `is_dummy` field must be updated manually
/// in case it corresponds to a dummy segment.
#[allow(clippy::unwrap_or_default)]
fn build_segment_data<F: RichField>(
    segment_index: usize,
    registers_before: Option<RegistersState>,
    registers_after: Option<RegistersState>,
    memory: Option<MemoryState>,
    interpreter: &Interpreter<F>,
) -> GenerationSegmentData {
    GenerationSegmentData {
        is_dummy: false,
        segment_index,
        registers_before: registers_before.unwrap_or(RegistersState::new()),
        registers_after: registers_after.unwrap_or(RegistersState::new()),
        memory: memory.unwrap_or_default(),
        max_cpu_len_log: interpreter.get_max_cpu_len_log(),
        extra_data: ExtraSegmentData {
            bignum_modmul_result_limbs: interpreter
                .generation_state
                .bignum_modmul_result_limbs
                .clone(),
            rlp_prover_inputs: interpreter.generation_state.rlp_prover_inputs.clone(),
            withdrawal_prover_inputs: interpreter
                .generation_state
                .withdrawal_prover_inputs
                .clone(),
            trie_root_ptrs: interpreter.generation_state.trie_root_ptrs.clone(),
            jumpdest_table: interpreter.generation_state.jumpdest_table.clone(),
            next_txn_index: interpreter.generation_state.next_txn_index,
        },
    }
}

pub struct SegmentDataIterator<'a> {
    pub partial_next_data: Option<GenerationSegmentData>,
    pub inputs: &'a GenerationInputs,
    pub max_cpu_len_log: Option<usize>,
}

type F = GoldilocksField;
impl<'a> Iterator for SegmentDataIterator<'a> {
    type Item = (GenerationInputs, GenerationSegmentData);

    fn next(&mut self) -> Option<Self::Item> {
        let cur_and_next_data = generate_next_segment::<F>(
            self.max_cpu_len_log,
            self.inputs,
            self.partial_next_data.clone(),
        );

        if cur_and_next_data.is_some() {
            let (data, next_data) = cur_and_next_data.expect("Data cannot be `None`");
            self.partial_next_data = next_data;
            Some((self.inputs.clone(), data))
        } else {
            None
        }
    }
}

/// Returns the data for the current segment, as well as the data -- except
/// registers_after -- for the next segment.
pub(crate) fn generate_next_segment<F: RichField>(
    max_cpu_len_log: Option<usize>,
    inputs: &GenerationInputs,
    partial_segment_data: Option<GenerationSegmentData>,
) -> Option<(GenerationSegmentData, Option<GenerationSegmentData>)> {
    let mut interpreter = Interpreter::<F>::new_with_generation_inputs(
        KERNEL.global_labels["init"],
        vec![],
        inputs,
        max_cpu_len_log,
    );

    // Get the (partial) current segment data, if it is provided. Otherwise,
    // initialize it.
    let mut segment_data = if let Some(partial) = partial_segment_data {
        if partial.registers_after.program_counter == KERNEL.global_labels["halt"] {
            return None;
        }
        interpreter
            .get_mut_generation_state()
            .set_segment_data(&partial);
        interpreter.generation_state.memory = partial.memory.clone();
        partial
    } else {
        build_segment_data(0, None, None, None, &interpreter)
    };

    let segment_index = segment_data.segment_index;

    // Run the interpreter to get `registers_after` and the partial data for the
    // next segment.
    if let Ok((updated_registers, mem_after)) =
        set_registers_and_run(segment_data.registers_after, &mut interpreter)
    {
        // Set `registers_after` correctly and push the data.
        let before_registers = segment_data.registers_after;

        let partial_segment_data = Some(build_segment_data(
            segment_index + 1,
            Some(updated_registers),
            Some(updated_registers),
            mem_after,
            &interpreter,
        ));

        segment_data.registers_after = updated_registers;
        Some((segment_data, partial_segment_data))
    } else {
        panic!("Segment generation failed");
    }
}

/// Returns a vector containing the data required to generate all the segments
/// of a transaction.
pub fn generate_all_data_segments<F: RichField>(
    max_cpu_len_log: Option<usize>,
    inputs: &GenerationInputs,
) -> anyhow::Result<Vec<GenerationSegmentData>> {
    let mut all_seg_data = vec![];

    let mut interpreter = Interpreter::<F>::new_with_generation_inputs(
        KERNEL.global_labels["init"],
        vec![],
        inputs,
        max_cpu_len_log,
    );

    let mut segment_index = 0;

    let mut segment_data = build_segment_data(segment_index, None, None, None, &interpreter);

    while segment_data.registers_after.program_counter != KERNEL.global_labels["halt"] {
        let (updated_registers, mem_after) =
            set_registers_and_run(segment_data.registers_before, &mut interpreter)?;

        // Set `registers_after` correctly and push the data.
        segment_data.registers_after = updated_registers;
        all_seg_data.push(segment_data);

        segment_index += 1;

        segment_data = build_segment_data(
            segment_index,
            Some(updated_registers),
            Some(updated_registers),
            mem_after,
            &interpreter,
        );
    }

    Ok(all_seg_data)
}

/// A utility module designed to test witness generation externally.
pub mod testing {
    use super::*;
    use crate::{
        cpu::kernel::interpreter::Interpreter,
        generation::{output_debug_tries, state::State},
    };

    /// Simulates the zkEVM CPU execution.
    /// It does not generate any trace or proof of correct state transition.
    pub fn simulate_execution<F: RichField>(inputs: GenerationInputs) -> Result<()> {
        let initial_stack = vec![];
        let initial_offset = KERNEL.global_labels["init"];
        let mut interpreter: Interpreter<F> =
            Interpreter::new_with_generation_inputs(initial_offset, initial_stack, &inputs, None);
        let result = interpreter.run();
        if result.is_err() {
            output_debug_tries(interpreter.get_generation_state())?;
        }

        result?;
        Ok(())
    }

    pub fn prove_all_segments<F, C, const D: usize>(
        all_stark: &AllStark<F, D>,
        config: &StarkConfig,
        inputs: GenerationInputs,
        max_cpu_len_log: usize,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> Result<Vec<AllProof<F, C, D>>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let mut segment_idx = 0;
        let mut data = generate_all_data_segments::<F>(Some(max_cpu_len_log), &inputs)?;

        let mut proofs = Vec::with_capacity(data.len());
        for mut d in data {
            let proof = prove(
                all_stark,
                config,
                inputs.clone(),
                &mut d,
                timing,
                abort_signal.clone(),
            )?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    pub fn prove_all_segments_batch<F, P, C, const D: usize>(
        all_stark: &AllStark<F, D>,
        config: &StarkConfig,
        inputs: GenerationInputs,
        max_cpu_len_log: usize,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> Result<Vec<BatchStarkProofWithPublicInputs<F, C, D, NUM_TABLES>>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        P: PackedField<Scalar = F>,
    {
        let mut segment_idx = 0;
        let mut data = generate_all_data_segments::<F>(Some(max_cpu_len_log), &inputs)?;

        let mut proofs = Vec::with_capacity(data.len());
        for mut d in data {
            let proof = prove_batch::<F, P, C, D>(
                all_stark,
                config,
                inputs.clone(),
                &mut d,
                timing,
                abort_signal.clone(),
            )?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    pub fn simulate_all_segments_interpreter<F>(
        inputs: GenerationInputs,
        max_cpu_len_log: usize,
    ) -> anyhow::Result<()>
    where
        F: RichField,
    {
        let max_cpu_len_log = Some(max_cpu_len_log);
        let mut interpreter = Interpreter::<F>::new_with_generation_inputs(
            KERNEL.global_labels["init"],
            vec![],
            &inputs,
            max_cpu_len_log,
        );

        let mut segment_index = 0;

        let mut segment_data = build_segment_data(segment_index, None, None, None, &interpreter);

        while segment_data.registers_after.program_counter != KERNEL.global_labels["halt"] {
            segment_index += 1;

            let (updated_registers, mem_after) =
                set_registers_and_run(segment_data.registers_before, &mut interpreter)?;

            segment_data = build_segment_data(
                segment_index,
                Some(updated_registers),
                Some(updated_registers),
                mem_after,
                &interpreter,
            );
        }

        Ok(())
    }
}
