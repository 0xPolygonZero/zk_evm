use crate::{
    aliased_crate_types::SmtGenerationInputs, decoding::TraceDecodingResult,
    processed_block_trace_smt::SmtProcessedBlockTrace, types::OtherBlockData,
};

impl SmtProcessedBlockTrace {
    pub(crate) fn into_proof_gen_smt_ir(
        self,
        _other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<SmtGenerationInputs>> {
        todo!()
    }
}
