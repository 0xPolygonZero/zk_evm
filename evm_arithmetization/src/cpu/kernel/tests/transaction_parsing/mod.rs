use anyhow::{anyhow, Result};
use plonky2::field::types::Field;

use crate::{cpu::kernel::interpreter::Interpreter, memory::segments::Segment};

mod parse_type_0_txn;
mod parse_type_1_txn;
mod parse_type_2_txn;
mod parse_type_3_txn;

pub(crate) fn prepare_interpreter_for_txn_parsing<F: Field>(
    interpreter: &mut Interpreter<F>,
    entry_point: usize,
    exit_point: usize,
    txn: Vec<u8>,
) -> Result<()> {
    let retaddr = 0xDEADBEEFu32.into();
    const INITIAL_TXN_RLP_ADDR: usize = Segment::RlpRaw as usize + 1;

    interpreter.generation_state.registers.program_counter = entry_point;
    interpreter.push(retaddr).or(Err(anyhow!(
        "Error in `prepare_interpreter_for_txn_parsing`."
    )))?;
    interpreter
        .push(INITIAL_TXN_RLP_ADDR.into())
        .or(Err(anyhow!(
            "Error in `prepare_interpreter_for_txn_parsing`."
        )))?;

    // When we reach process_normalized_txn, we're done with parsing and
    // normalizing. Processing normalized transactions is outside the scope of
    // this test.
    interpreter.halt_offsets.push(exit_point);
    interpreter.extend_memory_segment_bytes(Segment::RlpRaw, txn);

    Ok(())
}
