use ethereum_types::{Address, U256};

use crate::{
    aliased_crate_types::SmtGenerationInputs,
    decoding_smt::SmtTraceParsingResult,
    processed_block_trace::{CodeHashMeta, ProcessedBlockTrace},
    trace_protocol::BlockTrace,
    types::{InsertCodeFunc, OtherBlockData, ResolveFunc},
};
pub(crate) type SmtProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceSmtSpec>;

/// Smt processed pre-image.
#[derive(Clone, Debug)]
pub struct SmtProcessedBlockTracePreImage {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

impl BlockTrace {
    /// Process the block trace into SMT IR.
    pub fn into_proof_gen_smt_ir(
        self,
        _other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>> {
        todo!()
    }

    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn smt_into_proof_gen_ir<F, G>(
        self,
        cmeta: &CodeHashMeta<F, G>,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>>
    where
        F: ResolveFunc,
        G: InsertCodeFunc,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(cmeta, other_data.b_data.withdrawals.clone())?;

        processed_block_trace.into_proof_gen_ir(other_data)
    }

    fn into_smt_processed_block_trace<F, G>(
        self,
        cmeta: &CodeHashMeta<F, G>,
        withdrawals: Vec<(Address, U256)>,
    ) -> SmtTraceParsingResult<SmtProcessedBlockTrace>
    where
        F: ResolveFunc,
        G: InsertCodeFunc,
    {
        let _ = cmeta;
        let _ = withdrawals;
        todo!()
    }
}
