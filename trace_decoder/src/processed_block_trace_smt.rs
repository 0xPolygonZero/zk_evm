use std::collections::HashMap;

use ethereum_types::H256;
use ethereum_types::{Address, U256};

use crate::types::CodeHash;
use crate::{
    aliased_crate_types::SmtGenerationInputs,
    decoding_mpt::CodeHashResolver,
    decoding_smt::SmtTraceParsingResult,
    processed_block_trace::ProcessedBlockTrace,
    trace_protocol::BlockTrace,
    types::{CodeHashResolveFunc, OtherBlockData},
};
pub(crate) type SmtProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceSmtSpec>;

/// Smt processed pre-image.
#[derive(Clone, Debug)]
pub struct SmtProcessedBlockTracePreImage {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

#[allow(dead_code)]
struct SMTCodeHashResolving<F> {
    /// If we have not seen this code hash before, use the resolve function that
    /// the client passes down to us. This will likely be an rpc call/cache
    /// check.
    client_code_hash_resolve_f: F,

    /// Code hash mappings that we have constructed from parsing the block
    /// trace. If there are any txns that create contracts, then they will also
    /// get added here as we process the deltas.
    extra_code_hash_mappings: HashMap<CodeHash, Vec<u8>>,
}

impl<F: CodeHashResolveFunc> CodeHashResolver for SMTCodeHashResolving<F> {
    fn resolve(&mut self, c_hash: &CodeHash) -> Vec<u8> {
        match self.extra_code_hash_mappings.get(c_hash) {
            Some(code) => code.clone(),
            None => (self.client_code_hash_resolve_f)(c_hash),
        }
    }

    fn insert_code(&mut self, c_hash: H256, code: Vec<u8>) {
        self.extra_code_hash_mappings.insert(c_hash, code);
    }
}

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
    pub fn smt_into_proof_gen_ir<F>(
        self,
        c_resolve: &CodeHashResolveFunc,
        other_data: OtherBlockData,
    ) -> SmtTraceParsingResult<Vec<SmtGenerationInputs>>
    where
        F: CodeHashResolver,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(c_resolve, other_data.b_data.withdrawals.clone())?;

        processed_block_trace.into_proof_gen_ir(other_data)
    }

    fn into_smt_processed_block_trace(
        self,
        c_resolve: &CodeHashResolveFunc,
        withdrawals: Vec<(Address, U256)>,
    ) -> SmtTraceParsingResult<SmtProcessedBlockTrace> {
        let _ = c_resolve;
        let _ = withdrawals;
        todo!()
    }
}
