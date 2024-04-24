use ethereum_types::{Address, U256};

use crate::{
    aliased_crate_types::GenerationInputs,
    decoding_smt::{SmtTraceParsingError, SmtTraceParsingResult},
    decoding_traits::ProcessableBlockTrace,
    processed_block_trace::ProcessedBlockTrace,
    processed_block_trace_mpt::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHashResolveFunc, OtherBlockData},
};

pub(crate) type SmtProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceSmtSpec>;

#[derive(Clone, Debug)]
pub(crate) struct SmtProcessedBlockTracePreImages {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

impl ProcessableBlockTrace for SmtProcessedBlockTrace {
    type Ir = GenerationInputs;
    type Error = SmtTraceParsingError;

    fn into_proof_gen_ir(self, _other_data: OtherBlockData) -> Result<Vec<Self::Ir>, Self::Error> {
        todo!()
    }
}

impl BlockTrace {
    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn smt_into_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<GenerationInputs>>
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
        let _ = p_meta;
        let _ = withdrawals;
        todo!()
    }
}
