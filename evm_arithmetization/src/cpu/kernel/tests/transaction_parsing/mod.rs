use anyhow::{anyhow, Result};
use plonky2::hash::hash_types::RichField;

use crate::{
    cpu::kernel::{constants::INITIAL_RLP_ADDR, interpreter::Interpreter},
    memory::segments::Segment,
};

mod parse_type_0_txn;
mod parse_type_1_txn;
mod parse_type_2_txn;
#[cfg(feature = "eth_mainnet")]
mod parse_type_3_txn;

pub(crate) fn prepare_interpreter_for_txn_parsing<F: RichField>(
    interpreter: &mut Interpreter<F>,
    entry_point: usize,
    exit_point: usize,
    txn: Vec<u8>,
) -> Result<()> {
    let retaddr = 0xDEADBEEFu32.into();

    interpreter.generation_state.registers.program_counter = entry_point;
    interpreter.push(retaddr).or(Err(anyhow!(
        "Error in `prepare_interpreter_for_txn_parsing`."
    )))?;
    interpreter.push(INITIAL_RLP_ADDR.1.into()).or(Err(anyhow!(
        "Error in `prepare_interpreter_for_txn_parsing`."
    )))?;

    // When we reach process_normalized_txn, we're done with parsing and
    // normalizing. Processing normalized transactions is outside the scope of
    // this test.
    interpreter.halt_offsets.push(exit_point);
    // Clear the RlpRaw segment (the first byte contains the empty node encoding).
    interpreter.generation_state.memory.contexts[0].segments[Segment::RlpRaw.unscale()]
        .content
        .truncate(1);
    interpreter.extend_memory_segment_bytes(Segment::RlpRaw, txn);

    Ok(())
}
