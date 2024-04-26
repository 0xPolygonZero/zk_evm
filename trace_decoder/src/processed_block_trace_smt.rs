use ethereum_types::{Address, U256};
use thiserror::Error;

use crate::{
    aliased_crate_types::{MptGenerationInputs, SmtGenerationInputs},
    decoding_smt::{SmtTraceParsingError, SmtTraceParsingResult},
    processed_block_trace::ProcessedBlockTrace,
    processed_block_trace_mpt::{MptProcessedBlockTrace, ProcessingMeta},
    trace_protocol::BlockTrace,
    types::{CodeHashResolveFunc, OtherBlockData},
};

pub(crate) type SmtProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceSmtSpec>;

#[derive(Clone, Debug)]
pub(crate) struct SmtProcessedBlockTracePreImages {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

impl BlockTrace {
    pub(crate) fn into_proof_gen_ir(
        self,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>> {
        todo!()
    }

    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn smt_into_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        processed_block_trace.into_proof_gen_ir(other_data)
    }

    fn into_smt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> SmtTraceParsingResult<SmtProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        todo!()
    }
}
