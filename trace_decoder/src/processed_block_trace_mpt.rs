//! Defines functions that processes a [BlockTrace] into the mpt format so that
//! it is easier to turn the block transactions into IRs.

use std::collections::HashMap;
use std::fmt::Debug;

use mpt_trie::partial_trie::PartialTrie;

use crate::compact::compact_mpt_processing::MptPreImageProcessing;
use crate::decoding::TraceDecodingResult;
use crate::processed_block_trace::BlockTraceProcessing;
use crate::processed_block_trace::ProcessedBlockTrace;
use crate::protocol_processing::process_block_trace_trie_pre_images;
use crate::trace_protocol::BlockTraceTriePreImages;
use crate::types::{CodeHash, CodeHashResolveFunc, HashedAccountAddr};
use crate::{
    aliased_crate_types::AccountRlp,
    compact::{
        compact_mpt_processing::MptPartialTriePreImages,
        compact_processing_common::ProcessedCompactOutput,
        compact_to_mpt_trie::StateTrieExtractionOutput,
    },
    decoding_mpt::MptBlockTraceDecoding,
};

pub(crate) type MptProcessedBlockTrace =
    ProcessedBlockTrace<ProcedBlockTraceMptSpec, MptBlockTraceDecoding>;

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceMptSpec {
    pub(crate) tries: MptPartialTriePreImages,
}

pub(crate) struct MptBlockTraceProcessing;

impl BlockTraceProcessing for MptBlockTraceProcessing {
    type ProcessedPreImage = MptProcessedBlockTracePreImages;
    type Output = ProcedBlockTraceMptSpec;

    fn process_block_trace(
        image: BlockTraceTriePreImages,
    ) -> TraceDecodingResult<Self::ProcessedPreImage> {
        process_block_trace_trie_pre_images::<MptPreImageProcessing>(image)
            .map(|image| image.into())
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
                .map(|data| (addr.into(), rlp::decode::<AccountRlp>(data).unwrap()))
        })
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        image.extra_code_hash_mappings.as_ref()
    }

    fn create_spec_output(image: Self::ProcessedPreImage) -> Self::Output {
        ProcedBlockTraceMptSpec { tries: image.tries }
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
