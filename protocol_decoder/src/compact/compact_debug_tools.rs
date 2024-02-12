// Using struct to make printing this nicer easier.
#[derive(Debug)]
pub struct InstructionAndBytesParsedFromBuf(Vec<(Instruction, Vec<u8>)>);

impl From<Vec<(Instruction, Vec<u8>)>> for InstructionAndBytesParsedFromBuf {
    fn from(v: Vec<(Instruction, Vec<u8>)>) -> Self {
        Self(v)
    }
}

// TODO: Move behind a feature flag just used for debugging (but probably not
// `debug`)...
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

