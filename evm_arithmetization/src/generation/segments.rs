//! Module defining the logic around proof segmentation into chunks,
//! which allows what is commonly known as zk-continuations.

use anyhow::Result;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use super::TrimmedGenerationInputs;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::{set_registers_and_run, ExtraSegmentData, Interpreter};
use crate::generation::state::State;
use crate::generation::{collect_debug_tries, debug_inputs, ErrorWithTries, GenerationInputs};
use crate::witness::memory::MemoryState;
use crate::witness::state::RegistersState;

/// Structure holding the data needed to initialize a segment.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct GenerationSegmentData {
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
    /// Retrieves the index of this segment.
    pub const fn segment_index(&self) -> usize {
        self.segment_index
    }
}

/// Builds a new `GenerationSegmentData`.
#[allow(clippy::unwrap_or_default)]
fn build_segment_data<F: RichField>(
    segment_index: usize,
    registers_before: Option<RegistersState>,
    registers_after: Option<RegistersState>,
    memory: Option<MemoryState>,
    interpreter: &Interpreter<F>,
) -> GenerationSegmentData {
    GenerationSegmentData {
        segment_index,
        registers_before: registers_before.unwrap_or(RegistersState::new()),
        registers_after: registers_after.unwrap_or(RegistersState::new()),
        memory: memory.unwrap_or(MemoryState {
            preinitialized_segments: interpreter
                .generation_state
                .memory
                .preinitialized_segments
                .clone(),
            ..Default::default()
        }),
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
            ger_prover_inputs: interpreter.generation_state.ger_prover_inputs.clone(),
            trie_root_ptrs: interpreter.generation_state.trie_root_ptrs.clone(),
            jumpdest_table: interpreter.generation_state.jumpdest_table.clone(),
            next_txn_index: interpreter.generation_state.next_txn_index,
            access_lists_ptrs: interpreter.generation_state.access_lists_ptrs.clone(),
            state_ptrs: interpreter.generation_state.state_ptrs.clone(),
        },
    }
}

pub struct SegmentDataIterator<F: RichField> {
    interpreter: Interpreter<F>,
    partial_next_data: Option<GenerationSegmentData>,
}

pub type SegmentRunResult = Option<Box<(GenerationSegmentData, Option<GenerationSegmentData>)>>;

#[derive(thiserror::Error, Debug, Serialize, Deserialize)]
#[error("{}", .message)]
pub struct SegmentError {
    pub message: String,
}

impl<F: RichField> SegmentDataIterator<F> {
    pub fn new(inputs: &GenerationInputs<F>, max_cpu_len_log: Option<usize>) -> Self {
        debug_inputs(inputs);

        let interpreter = Interpreter::<F>::new_with_generation_inputs(
            KERNEL.global_labels["init"],
            vec![],
            inputs,
            max_cpu_len_log,
        );

        Self {
            interpreter,
            partial_next_data: None,
        }
    }

    /// Returns the data for the current segment, as well as the data -- except
    /// registers_after -- for the next segment.
    fn generate_next_segment(
        &mut self,
        partial_segment_data: Option<GenerationSegmentData>,
    ) -> Result<SegmentRunResult, ErrorWithTries<SegmentError>> {
        // Get the (partial) current segment data, if it is provided. Otherwise,
        // initialize it.
        let mut segment_data = if let Some(partial) = partial_segment_data {
            if partial.registers_after.program_counter == KERNEL.global_labels["halt"] {
                return Ok(None);
            }
            self.interpreter
                .get_mut_generation_state()
                .set_segment_data(&partial);
            self.interpreter.generation_state.memory = partial.memory.clone();
            partial
        } else {
            build_segment_data(0, None, None, None, &self.interpreter)
        };

        let segment_index = segment_data.segment_index;

        // Run the interpreter to get `registers_after` and the partial data for the
        // next segment.
        let execution_result =
            set_registers_and_run(segment_data.registers_after, &mut self.interpreter);
        if let Ok((updated_registers, mem_after)) = execution_result {
            let partial_segment_data = Some(build_segment_data(
                segment_index + 1,
                Some(updated_registers),
                Some(updated_registers),
                mem_after,
                &self.interpreter,
            ));

            segment_data.registers_after = updated_registers;
            Ok(Some(Box::new((segment_data, partial_segment_data))))
        } else {
            let inputs = &self.interpreter.get_generation_state().inputs;
            let block = inputs.block_metadata.block_number;
            let txn_range = match inputs.txn_hashes.len() {
                0 => "Dummy".to_string(),
                1 => format!("{:?}", inputs.txn_number_before),
                _ => format!(
                    "{:?}_{:?}",
                    inputs.txn_number_before,
                    inputs.txn_number_before + inputs.txn_hashes.len()
                ),
            };
            // In case of the error, return tries as part of the error for easier debugging.
            Err(ErrorWithTries::new(
                SegmentError {
                    message: format!(
                        "Segment generation {:?} for block:{} batch:{} tx_range:({}) failed with error {:?}",
                        segment_index,
                        block.low_u64(),
                        segment_index,
                        txn_range,
                        execution_result.unwrap_err()
                    ),
                },
                collect_debug_tries(self.interpreter.get_generation_state()),
            ))
        }
    }
}

/// Returned type from a `SegmentDataIterator`, needed to prove all segments in
/// a transaction batch.
pub type AllData<F> =
    Result<(TrimmedGenerationInputs<F>, GenerationSegmentData), ErrorWithTries<SegmentError>>;

impl<F: RichField> Iterator for SegmentDataIterator<F> {
    type Item = AllData<F>;

    fn next(&mut self) -> Option<Self::Item> {
        let run = self.generate_next_segment(self.partial_next_data.clone());

        if let Ok(segment_run) = run {
            match segment_run {
                // The run was valid, but didn't not consume the payload fully.
                Some(boxed) => {
                    let (data, next_data) = *boxed;
                    self.partial_next_data = next_data;
                    Some(Ok((self.interpreter.generation_state.inputs.clone(), data)))
                }
                // The payload was fully consumed.
                None => None,
            }
        } else {
            // The run encountered some error.
            Some(Err(run.unwrap_err()))
        }
    }
}
