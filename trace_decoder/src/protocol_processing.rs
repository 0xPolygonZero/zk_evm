//! Logic to processes the "outer" structure of the protocol payload. All
//! "inner" complex logic (eg. compact decoding) is handled in separate
//! dedicated modules.

use std::collections::HashMap;

use crate::aliased_crate_types::{HashedPartialTrie, PreImageProcessing};
use crate::{
    compact::compact_processing_common::{
        CompactParsingError, CompactParsingResult, ProcessedCompactOutput,
    },
    decoding::{TraceDecodingError, TraceDecodingResult},
    trace_protocol::{
        BlockTraceTriePreImages, CombinedPreImages, SeparateStorageTriesPreImage,
        SeparateTriePreImage, SeparateTriePreImages, TrieCompact, TrieUncompressed,
    },
    types::HashedAccountAddr,
};

pub(crate) trait ProtocolPreImageProcessing {
    type ProcessedPreImage;

    fn process_image(
        bytes: Vec<u8>,
    ) -> CompactParsingResult<ProcessedCompactOutput<Self::ProcessedPreImage>>;
    fn process_image_debug(
        bytes: Vec<u8>,
    ) -> CompactParsingResult<ProcessedCompactOutput<Self::ProcessedPreImage>>;

    fn expected_header_version() -> u8;
}

pub fn process_block_trace_trie_pre_images(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> TraceDecodingResult<
    ProcessedCompactOutput<<PreImageProcessing as ProtocolPreImageProcessing>::ProcessedPreImage>,
> {
    process_block_trace_trie_pre_images_intern::<PreImageProcessing>(block_trace_pre_images)
}

fn process_block_trace_trie_pre_images_intern<P: ProtocolPreImageProcessing>(
    block_trace_pre_images: BlockTraceTriePreImages,
) -> TraceDecodingResult<ProcessedCompactOutput<P::ProcessedPreImage>> {
    match block_trace_pre_images {
        BlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images::<P>(t),
        BlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images::<P>(t),
    }
}

fn process_combined_trie_pre_images<P: ProtocolPreImageProcessing>(
    tries: CombinedPreImages,
) -> TraceDecodingResult<ProcessedCompactOutput<P::ProcessedPreImage>> {
    process_compact_trie::<P>(tries.compact).map_err(TraceDecodingError::from)
}

fn process_separate_trie_pre_images<P: ProtocolPreImageProcessing>(
    _tries: SeparateTriePreImages,
) -> TraceDecodingResult<ProcessedCompactOutput<P::ProcessedPreImage>> {
    todo!()
}

fn process_state_trie(trie: SeparateTriePreImage) -> HashedPartialTrie {
    match trie {
        SeparateTriePreImage::Uncompressed(_) => todo!(),
        SeparateTriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: SeparateStorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        SeparateStorageTriesPreImage::SingleTrie(t) => process_single_combined_storage_tries(t),
        SeparateStorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_combined_storage_tries(
    _trie: TrieUncompressed,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, SeparateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie<P: ProtocolPreImageProcessing>(
    trie: TrieCompact,
) -> CompactParsingResult<ProcessedCompactOutput<P::ProcessedPreImage>> {
    let out = P::process_image(trie.0)?;
    let expected_header_version = P::expected_header_version();

    if !out.header.version_is_compatible(expected_header_version) {
        return Err(CompactParsingError::IncompatibleVersion(
            expected_header_version,
            out.header.version,
        ));
    }

    Ok(out)
}
