//! Logic intended just for debugging.
use super::compact_processing_common::{
    get_bytes_from_cursor, CompactCursor, CompactParsingResult, DebugCompactCursor, Instruction,
    WitnessBytes, WitnessEntries, WitnessEntry,
};

// Using struct to make printing this nicer easier.
/// Helpful wrapper to help returned tuples from getting too big.
#[derive(Debug)]
pub struct InstructionAndBytesParsedFromBuf(Vec<(Instruction, Vec<u8>)>);

impl From<Vec<(Instruction, Vec<u8>)>> for InstructionAndBytesParsedFromBuf {
    fn from(v: Vec<(Instruction, Vec<u8>)>) -> Self {
        Self(v)
    }
}

// TODO: Move behind a feature flag just used for debugging (but probably not
// `debug`)...
/// Parse the compact bytes just to instructions and do not process any further.
/// Intended for debugging purposes.
pub fn parse_just_to_instructions(bytes: Vec<u8>) -> CompactParsingResult<Vec<Instruction>> {
    let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(bytes);
    let (_, entries) = witness_bytes.process_into_instructions_and_header()?;

    Ok(entries
        .intern
        .into_iter()
        .map(|entry| match entry {
            WitnessEntry::Instruction(instr) => instr,
            _ => unreachable!(
                "Found a non-instruction at a stage when we should only have instructions!"
            ),
        })
        .collect())
}

impl WitnessEntries {
    // TODO: Also move behind a feature flag...
    fn parse_to_instructions_and_bytes_for_instruction(
        bytes: Vec<u8>,
    ) -> (InstructionAndBytesParsedFromBuf, CompactParsingResult<()>) {
        let witness_bytes = WitnessBytes::<DebugCompactCursor>::new(bytes);
        witness_bytes
        .process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure()
    }
}

impl<C: CompactCursor> WitnessBytes<C> {
    // TODO: Look at removing code duplication...
    // TODO: Move behind a feature flag...
    // TODO: Fairly hacky...
    // TODO: Replace `unwrap()`s with `Result`s?
    fn process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure(
        self,
    ) -> (InstructionAndBytesParsedFromBuf, CompactParsingResult<()>) {
        let mut instr_and_bytes_buf = Vec::new();
        let res = self.process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure_intern(&mut instr_and_bytes_buf);

        (instr_and_bytes_buf.into(), res)
    }

    fn process_into_instructions_and_keep_bytes_parsed_to_instruction_and_bail_on_first_failure_intern(
        mut self,
        instr_and_bytes_buf: &mut Vec<(Instruction, Vec<u8>)>,
    ) -> CompactParsingResult<()> {
        // Skip header.
        self.byte_cursor.intern().set_position(1);

        loop {
            let op_start_pos = self.byte_cursor.intern().position();
            self.process_operator()?;

            let instr_bytes = get_bytes_from_cursor(&mut self.byte_cursor, op_start_pos);

            let instr_added = self
                .instrs
                .intern
                .front()
                .cloned()
                .unwrap()
                .into_instruction()
                .unwrap();

            instr_and_bytes_buf.push((instr_added, instr_bytes));

            if self.byte_cursor.at_eof() {
                break;
            }
        }

        Ok(())
    }
}
