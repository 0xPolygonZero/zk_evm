use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use itertools::Itertools;
use once_cell::sync::Lazy;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{get_ctl_data, CtlData};
use starky::lookup::GrandProductChallengeSet;
use starky::proof::{MultiProof, StarkProofWithMetadata};
use starky::prover::prove_with_commitment;
use starky::stark::Stark;

use crate::all_stark::{all_cross_table_lookups, AllStark, Table, MEMORY_CTL_IDX, NUM_TABLES};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::generation::segments::GenerationSegmentData;
use crate::generation::{
    generate_traces, GenerationInputs, TablesWithPolynomialValues, TrimmedGenerationInputs,
};
use crate::get_challenges::observe_public_values;
use crate::proof::{AllProof, MemCap, PublicValues, DEFAULT_CAP_LEN};

/// Generate traces, then create all STARK proofs.
pub fn prove<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    inputs: TrimmedGenerationInputs,
    segment_data: &mut GenerationSegmentData,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<AllProof<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    features_check(&inputs);

    // Sanity check on the provided config
    assert_eq!(DEFAULT_CAP_LEN, 1 << config.fri_config.cap_height);

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

/// Compute all STARK proofs.
pub(crate) fn prove_with_traces<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: TablesWithPolynomialValues<F>,
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

    let enable_keccak_tables =
        trace_poly_values[*Table::Keccak].is_some() && trace_poly_values[*Table::KeccakSponge].is_some();

    // For each STARK, we compute the polynomial commitments for the polynomials
    // interpolating its trace.
    let trace_commitments = timed!(
        timing,
        "compute all trace commitments",
        trace_poly_values
            .iter()
            .zip_eq(Table::all())
            .map(|(trace_opt, table)| {
                trace_opt.as_ref().map(|trace| {
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
            })
            .collect::<Vec<_>>()
    );

    // Get the Merkle caps for all trace commitments and observe them.
    let trace_caps = trace_commitments
        .iter()
        .filter_map(|commitment_opt| commitment_opt.as_ref().map(|c| c.merkle_tree.cap.clone()))
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, C::Hasher>::new();
    for cap in &trace_caps {
        challenger.observe_cap(cap);
    }

    observe_public_values::<F, C, D>(&mut challenger, public_values)
        .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

    let cross_table_lookups = all_cross_table_lookups(enable_keccak_tables);

    // For each STARK, compute its cross-table lookup Z polynomials and get the
    // associated `CtlData`.
    let (ctl_challenges, ctl_data_per_table) = timed!(
        timing,
        "compute CTL data",
        get_ctl_data::<F, C, D, NUM_TABLES>(
            config,
            &trace_poly_values,
            &cross_table_lookups,
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
            MEMORY_CTL_IDX,
            get_memory_extra_looking_values(public_values),
        );
        check_ctls(
            &trace_poly_values,
            &cross_table_lookups,
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
    [Option<StarkProofWithMetadata<F, C, D>>; NUM_TABLES],
    MerkleCap<F, H>,
    MerkleCap<F, H>,
);

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
    trace_poly_values: &TablesWithPolynomialValues<F>,
    trace_commitments: Vec<Option<PolynomialBatch<F, C, D>>>,
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
    macro_rules! prove_table {
        ($stark:ident, $table:expr) => {
            if let (Some(trace_poly_values), Some(trace_commitment)) = (
                trace_poly_values[$table].as_ref(),
                trace_commitments[$table].as_ref(),
            ) {
                Some(
                    timed!(
                        timing,
                        &format!("prove {} STARK", stringify!($stark)),
                        prove_single_table(
                            &all_stark.$stark,
                            config,
                            trace_poly_values,
                            trace_commitment,
                            &ctl_data_per_table[$table],
                            ctl_challenges,
                            challenger,
                            timing,
                            abort_signal.clone(),
                        )?
                    )
                    .0,
                )
            } else {
                None
            }
        };
    }

    let arithmetic_proof = prove_table!(arithmetic_stark, *Table::Arithmetic);
    let byte_packing_proof = prove_table!(byte_packing_stark, *Table::BytePacking);
    let cpu_proof = prove_table!(cpu_stark, *Table::Cpu);
    let keccak_proof = prove_table!(keccak_stark, *Table::Keccak);
    let keccak_sponge_proof = prove_table!(keccak_sponge_stark, *Table::KeccakSponge);
    let logic_proof = prove_table!(logic_stark, *Table::Logic);
    let memory_proof = prove_table!(memory_stark, *Table::Memory);

    macro_rules! prove_mem_table {
        ($stark:ident, $table:expr) => {
            timed!(
                timing,
                &format!("prove {} STARK", stringify!($stark)),
                prove_single_table(
                    &all_stark.$stark,
                    config,
                    trace_poly_values[$table].as_ref().expect(&format!(
                        "Missing trace poly values for {:?}",
                        stringify!($table)
                    )),
                    trace_commitments[$table].as_ref().expect(&format!(
                        "Missing trace commitments for {:?}",
                        stringify!($table)
                    )),
                    &ctl_data_per_table[$table],
                    ctl_challenges,
                    challenger,
                    timing,
                    abort_signal.clone(),
                )?
            )
        };
    }

    let (mem_before_proof, mem_before_cap) = prove_mem_table!(mem_before_stark, *Table::MemBefore);
    let (mem_after_proof, mem_after_cap) = prove_mem_table!(mem_after_stark, *Table::MemAfter);

    #[cfg(feature = "cdk_erigon")]
    let poseidon_proof = prove_table!(poseidon_stark, *Table::Poseidon);

    Ok((
        [
            arithmetic_proof,
            byte_packing_proof,
            cpu_proof,
            keccak_proof,
            keccak_sponge_proof,
            logic_proof,
            memory_proof,
            Some(mem_before_proof),
            Some(mem_after_proof),
            #[cfg(feature = "cdk_erigon")]
            poseidon_proof,
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

/// Sanity checks on the consistency between this proof payload and the feature
/// flags being used.
pub(crate) fn features_check(inputs: &TrimmedGenerationInputs) {
    if cfg!(feature = "polygon_pos") || cfg!(feature = "cdk_erigon") {
        assert!(inputs.block_metadata.parent_beacon_block_root.is_zero());
        assert!(inputs.block_metadata.block_blob_gas_used.is_zero());
        assert!(inputs.block_metadata.block_excess_blob_gas.is_zero());
    }

    if !cfg!(feature = "cdk_erigon") {
        assert!(inputs.burn_addr.is_none());
    }
}

/// A utility module designed to test witness generation externally.
pub mod testing {
    use super::*;
    use crate::{
        cpu::kernel::interpreter::Interpreter,
        generation::{
            output_debug_tries,
            segments::{SegmentDataIterator, SegmentError},
            state::State,
        },
    };

    /// Simulates the zkEVM CPU execution.
    /// It does not generate any trace or proof of correct state transition.
    pub fn simulate_execution<F: RichField>(inputs: GenerationInputs) -> Result<()> {
        features_check(&inputs.clone().trim());

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
        let segment_data_iterator = SegmentDataIterator::<F>::new(&inputs, Some(max_cpu_len_log));
        let inputs = inputs.trim();
        let mut proofs = vec![];

        for segment_run in segment_data_iterator {
            let (_, mut next_data) =
                segment_run.map_err(|e: SegmentError| anyhow::format_err!(e))?;
            let proof = prove(
                all_stark,
                config,
                inputs.clone(),
                &mut next_data,
                timing,
                abort_signal.clone(),
            )?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    pub fn simulate_execution_all_segments<F>(
        inputs: GenerationInputs,
        max_cpu_len_log: usize,
    ) -> Result<()>
    where
        F: RichField,
    {
        features_check(&inputs.clone().trim());

        for segment in SegmentDataIterator::<F>::new(&inputs, Some(max_cpu_len_log)) {
            if let Err(e) = segment {
                return Err(anyhow::format_err!(e));
            }
        }

        Ok(())
    }
}
