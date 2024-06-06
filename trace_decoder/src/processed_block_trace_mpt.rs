//! Defines functions that processes a [BlockTrace] into the mpt format so that
//! it is easier to turn the block transactions into IRs.

use std::collections::HashMap;
use std::fmt::Debug;

use ethereum_types::Address;
use ethereum_types::U256;
use mpt_trie_normal::partial_trie::HashedPartialTrie;
use mpt_trie_normal::partial_trie::PartialTrie;

use crate::compact::compact_mpt_processing::MptPreImageProcessing;
use crate::decoding::TraceDecodingResult;
use crate::processed_block_trace::BlockTraceProcessing;
use crate::processed_block_trace::ProcessedBlockTrace;
use crate::processed_block_trace::ProcessingMeta;
use crate::protocol_processing::process_block_trace_trie_pre_images;
use crate::trace_protocol::BlockTrace;
use crate::trace_protocol::BlockTraceTriePreImages;
use crate::types::{CodeHash, CodeHashResolveFunc, HashedAccountAddr};
use crate::{
    aliased_crate_types::AccountRlp,
    compact::{
        compact_processing_common::ProcessedCompactOutput,
        compact_to_mpt_trie::StateTrieExtractionOutput,
    },
    decoding_mpt::MptBlockTraceDecoding,
};

pub(crate) type MptProcessedBlockTrace =
    ProcessedBlockTrace<MptPartialTriePreImages, MptBlockTraceDecoding>;

#[derive(Clone, Debug, Default)]
pub(crate) struct MptPartialTriePreImages {
    pub state: HashedPartialTrie,
    pub storage: HashMap<HashedAccountAddr, HashedPartialTrie>,
}

impl BlockTrace {
    pub(crate) fn into_mpt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceDecodingResult<MptProcessedBlockTrace>
    where
        F: CodeHashResolveFunc,
    {
        self.into_processed_block_trace::<_, MptBlockTraceProcessing, MptBlockTraceDecoding>(
            p_meta,
            withdrawals,
        )
    }
}

pub(crate) struct MptBlockTraceProcessing;

impl BlockTraceProcessing for MptBlockTraceProcessing {
    type ProcessedPreImage = MptProcessedBlockTracePreImages;
    type Output = MptPartialTriePreImages;

    fn process_block_trace(
        image: BlockTraceTriePreImages,
    ) -> TraceDecodingResult<Self::ProcessedPreImage> {
        process_block_trace_trie_pre_images::<MptPreImageProcessing>(image)
            .map(|image| image.into())
    }

    fn get_accounts(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<Item = (Address, crate::types::AccountInfo)> {
        image.


        // image.tries.state.items().filter_map(|(addr, data)| {
        //     data.as_val()
        //         .map(|data| (addr.into(), rlp::decode::<AccountRlp>(data).unwrap().into()))
        // })
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        image.extra_code_hash_mappings.as_ref()
    }

    fn create_spec_output(image: Self::ProcessedPreImage) -> Self::Output {
        MptPartialTriePreImages {
            state: image.tries.state,
            storage: image.tries.storage,
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
