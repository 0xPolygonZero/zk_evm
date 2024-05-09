use std::collections::HashMap;

use ethereum_types::{Address, U256};
use evm_arithmetization_mpt::generation::mpt::AccountRlp;

use crate::{
    aliased_crate_types::SmtGenerationInputs,
    decoding::TraceDecodingResult,
    processed_block_trace::{
        BlockTraceProcessing, ProcessedBlockTrace, ProcessedSectionInfo, ProcessingMeta,
    },
    protocol_processing::TraceProtocolDecodingResult,
    trace_protocol::{BlockTrace, TriePreImage},
    types::{CodeHash, CodeHashResolveFunc, HashedAccountAddr, OtherBlockData},
};

pub(crate) type SmtProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceSmtSpec, SmtBlockTraceProcessing>;

/// Smt processed pre-image.
#[derive(Clone, Debug)]
pub struct SmtProcessedBlockTracePreImage {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

struct SmtBlockTraceProcessing;

impl BlockTraceProcessing for SmtBlockTraceProcessing {
    type ProcessedPreImage = SmtProcessedBlockTracePreImage;
    type Output = ProcedBlockTraceSmtSpec;

    fn process_block_trace(
        image: TriePreImage,
    ) -> TraceProtocolDecodingResult<Self::ProcessedPreImage> {
        todo!()
    }

    fn get_account_keys(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<Item = (HashedAccountAddr, AccountRlp)> {
        todo!();

        std::iter::empty()
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        todo!()
    }

    fn create_spec_output(
        image: Self::ProcessedPreImage,
    ) -> Self::Output {
        todo!()
    }
}

impl BlockTrace {
    /// Process the block trace into SMT IR.
    pub fn into_proof_gen_smt_ir(
        self,
        _other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<SmtGenerationInputs>> {
        todo!()
    }

    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn smt_into_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceProtocolDecodingResult<Vec<SmtGenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }

    fn into_smt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceProtocolDecodingResult<SmtProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        self.into_processed_block_trace::<_, SmtBlockTraceProcessing>(p_meta, withdrawals)
    }
}
