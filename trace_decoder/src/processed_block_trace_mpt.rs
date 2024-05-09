use std::collections::HashMap;
use std::fmt::Debug;

use ethereum_types::{Address, U256};
use evm_arithmetization_mpt::GenerationInputs;
use mpt_trie::partial_trie::PartialTrie;

use crate::compact::{
    compact_mpt_processing::MptPartialTriePreImages,
    compact_processing_common::ProcessedCompactOutput,
    compact_to_mpt_trie::StateTrieExtractionOutput,
};
use crate::processed_block_trace::ProcessedBlockTrace;
use crate::protocol_processing::{
    process_mpt_block_trace_trie_pre_images, TraceProtocolDecodingResult,
};
use crate::trace_protocol::{BlockTrace, TriePreImage};
use crate::types::{
    CodeHash, CodeHashResolveFunc, HashedAccountAddr, HashedStorageAddrNibbles, OtherBlockData,
};
use crate::{
    aliased_crate_types::MptAccountRlp,
    processed_block_trace::{BlockTraceProcessing, ProcessedSectionInfo, ProcessingMeta},
};

pub(crate) type MptProcessedBlockTrace = ProcessedBlockTrace<ProcedBlockTraceMptSpec, MptBlockTraceProcessing>;

pub(crate) type StorageAccess = Vec<HashedStorageAddrNibbles>;
pub(crate) type StorageWrite = Vec<(HashedStorageAddrNibbles, Vec<u8>)>;

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceMptSpec {
    pub(crate) tries: MptPartialTriePreImages,
}

pub(crate) struct MptBlockTraceProcessing;

impl BlockTraceProcessing for MptBlockTraceProcessing {
    type ProcessedPreImage = MptProcessedBlockTracePreImages;
    type Output = ProcedBlockTraceMptSpec;

    fn process_block_trace(
        image: TriePreImage,
    ) -> TraceProtocolDecodingResult<Self::ProcessedPreImage> {
        process_mpt_block_trace_trie_pre_images(image)
    }

    fn get_account_keys(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<
        Item = (
            HashedAccountAddr,
            evm_arithmetization_mpt::generation::mpt::AccountRlp,
        ),
    > {
        image.tries.state.items().filter_map(|(addr, data)| {
            data.as_val()
                .map(|data| (addr.into(), rlp::decode::<MptAccountRlp>(data).unwrap()))
        })
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        image.extra_code_hash_mappings.as_ref()
    }

    fn create_spec_output(
        image: Self::ProcessedPreImage,
    ) -> Self::Output {
        ProcedBlockTraceMptSpec {
            tries: image.tries,
        }
    }
}

/// Mpt processed pre-image.
#[derive(Clone, Debug)]
pub struct MptProcessedBlockTracePreImages {
    pub(crate) tries: MptPartialTriePreImages,
    pub(crate) extra_code_hash_mappings: Option<HashMap<CodeHash, Vec<u8>>>,
}

impl From<ProcessedCompactOutput<StateTrieExtractionOutput>> for MptProcessedBlockTracePreImages {
    fn from(v: ProcessedCompactOutput<StateTrieExtractionOutput>) -> Self {
        let tries = MptPartialTriePreImages {
            state: v.witness_out.state_trie,
            storage: v.witness_out.storage_tries,
        };

        Self {
            tries,
            extra_code_hash_mappings: (!v.witness_out.code.is_empty())
                .then_some(v.witness_out.code),
        }
    }
}
