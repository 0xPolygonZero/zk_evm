//! Defines functions that processes a [BlockTrace] into the smt format so that
//! it is easier to turn the block transactions into IRs.

use std::collections::HashMap;

use ethereum_types::{Address, U256};
use smt_trie::{db::MemoryDb, smt::Smt};

use crate::{
    aliased_crate_types::{AccountRlp, GenerationInputs, TrieInputs, TrieRoots},
    compact::compact_to_smt_trie::SmtStateTrieExtractionOutput,
    decoding::{GenIr, ProcessedBlockTraceDecode, StateTrie, TraceDecodingResult, Trie},
    decoding_smt::{SmtBlockTraceDecoding, SmtTrieWrapped},
    processed_block_trace::{BlockTraceProcessing, ProcessedBlockTrace, ProcessingMeta},
    trace_protocol::{BlockTrace, BlockTraceTriePreImages},
    types::{AccountInfo, CodeHash, CodeHashResolveFunc, HashedAccountAddr, OtherBlockData},
};

pub(crate) type SmtProcessedBlockTrace =
    ProcessedBlockTrace<ProcedBlockTraceSmtSpec, SmtBlockTraceProcessing>;

#[derive(Clone, Debug, Default)]
pub(crate) struct ProcedBlockTraceSmtSpec {
    pub trie: SmtTrieWrapped,
}

struct SmtBlockTraceProcessing;

impl BlockTraceProcessing for SmtBlockTraceProcessing {
    type ProcessedPreImage = SmtStateTrieExtractionOutput;
    type Output = ProcedBlockTraceSmtSpec;

    fn process_block_trace(
        image: BlockTraceTriePreImages,
    ) -> TraceDecodingResult<Self::ProcessedPreImage> {
        todo!()
    }

    fn get_accounts(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<Item = (Address, AccountInfo)> {
        image.account_meta.iter().map(|(k, v)| (*k, v.clone()))
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        image.code.is_empty().then(|| &image.code)
    }

    fn create_spec_output(image: Self::ProcessedPreImage) -> Self::Output {
        ProcedBlockTraceSmtSpec { trie: image.trie }
    }
}

impl BlockTrace {
    pub(crate) fn into_smt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceDecodingResult<SmtProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        self.into_processed_block_trace::<_, SmtBlockTraceProcessing, SmtBlockTraceDecoding>(
            p_meta,
            withdrawals,
        )
    }
}
