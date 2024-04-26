use thiserror::Error;

use crate::{
    aliased_crate_types::{MptGenerationInputs, SmtGenerationInputs},
    processed_block_trace_smt::SmtProcessedBlockTrace,
    types::OtherBlockData,
};

/// Stores the result of parsing tries. Returns a [TraceParsingError] upon
/// failure.
pub type SmtTraceParsingResult<T> = Result<T, SmtTraceParsingError>;

/// Error from parsing an SMT trie.
#[derive(Clone, Debug, Error)]
pub enum SmtTraceParsingError {}

impl SmtProcessedBlockTrace {
    pub(crate) fn into_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>> {
        todo!()
    }
}
