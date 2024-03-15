use std::any::type_name;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, ensure, Result};
use ethereum_types::U256;
use hashbrown::HashMap;
use itertools::Itertools;
use once_cell::sync::Lazy;
use plonky2::field::extension::Extendable;
use plonky2::field::packable::Packable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, GenericHashOut};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{get_ctl_data, CtlData};
use starky::evaluation_frame::StarkEvaluationFrame;
use starky::lookup::{get_grand_product_challenge_set, GrandProductChallengeSet, Lookup};
use starky::proof::{MultiProof, StarkProofWithMetadata};
use starky::prover::prove_with_commitment;
use starky::stark::Stark;

use crate::all_stark::{AllStark, Table, NUM_TABLES};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::{generate_segment, ExtraSegmentData};
use crate::generation::state::GenerationState;
use crate::generation::{generate_traces, GenerationInputs, MemBeforeValues, SegmentData};
use crate::get_challenges::observe_public_values;
use crate::memory::segments::Segment;
use crate::proof::{AllProof, MemCap, PublicValues, RegistersData};
use crate::witness::memory::MemoryAddress;
use crate::witness::state::RegistersState;

/// Generate traces, then create all STARK proofs.
pub fn prove<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    inputs: GenerationInputs,
    max_cpu_len_log: usize,
    segment_index: usize,
    timing: &mut TimingTree,
    abort_signal: Option<Arc<AtomicBool>>,
) -> Result<Option<AllProof<F, C, D>>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    timed!(timing, "build kernel", Lazy::force(&KERNEL));
    if let Some((registers_before, registers_after, mut memory_before, extra_segment_data)) =
        generate_segment::<F>(max_cpu_len_log, segment_index, &inputs)?
    {
        let mut state = GenerationState::<F>::new(&inputs, &KERNEL.code)
            .map_err(|err| anyhow!("Failed to parse all the initial prover inputs: {:?}", err))?;
        state.registers = RegistersState {
            program_counter: state.registers.program_counter,
            is_kernel: state.registers.is_kernel,
            is_stack_top_read: false,
            check_overflow: false,
            ..registers_before
        };

        let ExtraSegmentData {
            trimmed_inputs,
            bignum_modmul_result_limbs,
            rlp_prover_inputs,
            withdrawal_prover_inputs,
            trie_root_ptrs,
            jumpdest_table,
        } = extra_segment_data.clone();

        state.inputs = trimmed_inputs;
        state.bignum_modmul_result_limbs = bignum_modmul_result_limbs;
        state.rlp_prover_inputs = rlp_prover_inputs;
        state.withdrawal_prover_inputs = withdrawal_prover_inputs;
        state.trie_root_ptrs = trie_root_ptrs;
        state.jumpdest_table = jumpdest_table;
        let mut shift_addr = MemoryAddress::new(0, Segment::ShiftTable, 0);
        let mut shift_val = U256::one();

        for _ in 0..256 {
            memory_before.set(shift_addr, shift_val);
            shift_addr.increment();
            shift_val <<= 1;
        }

        let actual_mem_before = {
            let mut res = vec![];
            for (ctx_idx, ctx) in memory_before.contexts.iter().enumerate() {
                for (segment_idx, segment) in ctx.segments.iter().enumerate() {
                    for (virt, value) in segment.content.iter().enumerate() {
                        if let &Some(val) = value {
                            res.push((
                                MemoryAddress {
                                    context: ctx_idx,
                                    segment: segment_idx,
                                    virt,
                                },
                                val,
                            ));
                        }
                    }
                }
            }
            res
        };

        let registers_data_before = RegistersData {
            program_counter: registers_before.program_counter.into(),
            is_kernel: (registers_before.is_kernel as u64).into(),
            stack_len: registers_before.stack_len.into(),
            stack_top: registers_before.stack_top,
            context: registers_before.context.into(),
            gas_used: registers_before.gas_used.into(),
        };
        let registers_data_after = RegistersData {
            program_counter: registers_after.program_counter.into(),
            is_kernel: (registers_after.is_kernel as u64).into(),
            stack_len: registers_after.stack_len.into(),
            stack_top: registers_after.stack_top,
            context: registers_after.context.into(),
            gas_used: registers_after.gas_used.into(),
        };
        let segment_data = SegmentData {
            max_cpu_len_log,
            starting_state: state,
            memory_before: actual_mem_before,
            registers_before: registers_data_before,
            registers_after: registers_data_after,
        };

        let (traces, mut public_values, final_values) = timed!(
            timing,
            "generate all traces",
            generate_traces(all_stark, inputs, config, segment_data, timing)?
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
        Ok(Some(proof))
    } else {
        Ok(None)
    }
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
) -> Result<(ProofWithMemCaps<F, C, C::Hasher, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let (arithmetic_proof, arithmetic_cap) = timed!(
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
    let (byte_packing_proof, bp_cap) = timed!(
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
    let (cpu_proof, cpu_cap) = timed!(
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
    let (keccak_proof, keccak_cap) = timed!(
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
    let (keccak_sponge_proof, keccak_sponge_cap) = timed!(
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
    let (logic_proof, logic_cap) = timed!(
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
    let (memory_proof, mem_cap) = timed!(
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

/// Returns a memory value in the form `(MemoryAddress, U256)`,
/// taken from a row in `MemAfterStark`.
pub(crate) fn get_mem_after_value_from_row<F: RichField>(row: &[F]) -> (MemoryAddress, U256) {
    // The row has shape (1, context, segment, virt, [values]) where [values] are 8
    // 32-bit elements representing one U256 word.
    let mem_address = MemoryAddress {
        context: row[1].to_canonical_u64() as usize,
        segment: row[2].to_canonical_u64() as usize,
        virt: row[3].to_canonical_u64() as usize,
    };

    let value: U256 = row[4..]
        .iter()
        .rev()
        .fold(0.into(), |acc, v| (acc << 32) + v.to_canonical_u64());
    (mem_address, value)
}

type ProofSingleWithCap<F, C, H, const D: usize> =
    (StarkProofWithMetadata<F, C, D>, MerkleCap<F, H>);

/// Computes a proof for a single STARK table, including:
/// - the initial state of the challenger,
/// - all the requires Merkle caps,
/// - all the required polynomial and FRI argument openings.
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
        max_cpu_len: usize,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> Result<Vec<AllProof<F, C, D>>>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let mut segment_idx = 0;
        let mut proofs = vec![];
        while let Some(proof) = prove(
            all_stark,
            config,
            inputs.clone(),
            max_cpu_len,
            segment_idx,
            timing,
            abort_signal.clone(),
        )? {
            segment_idx += 1;
            proofs.push(proof);
        }
        Ok(proofs)
    }

    pub fn simulate_all_segments_interpreter<F>(
        inputs: GenerationInputs,
        max_cpu_len_log: usize,
    ) -> anyhow::Result<()>
    where
        F: Field,
    {
        let mut index = 0;
        while generate_segment::<F>(max_cpu_len_log, index, &inputs)?.is_some() {
            index += 1;
        }
        Ok(())
    }
}
