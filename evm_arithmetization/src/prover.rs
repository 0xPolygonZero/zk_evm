use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use itertools::Itertools;
use once_cell::sync::Lazy;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};
use starky::config::StarkConfig;
use starky::cross_table_lookup::{get_ctl_data, CtlData};
use starky::lookup::GrandProductChallengeSet;
use starky::proof::{MultiProof, StarkProofWithMetadata};
use starky::prover::prove_with_commitment;
use starky::stark::Stark;

use crate::all_stark::{AllStark, Table, NUM_TABLES};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::{set_registers_and_run, ExtraSegmentData, Interpreter};
use crate::generation::state::GenerationState;
use crate::generation::{generate_traces, GenerationInputs};
use crate::get_challenges::observe_public_values;
use crate::memory::segments::Segment;
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
            trimmed_inputs: interpreter.generation_state.inputs.clone(),
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

            // Set `registers_after`.
            segment_data.registers_after = updated_registers;

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
