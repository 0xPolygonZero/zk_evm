//! Logic to processes the "outer" structure of the protocol payload. All
//! "inner" complex logic (eg. compact decoding) is handled in separate
//! dedicated modules.

use std::collections::HashMap;

use enum_as_inner::EnumAsInner;
use ethereum_types::{Address, U256};
use mpt_trie::partial_trie::HashedPartialTrie;
use thiserror::Error;

use crate::{
    compact::{
        compact_mpt_processing::{process_compact_mpt_prestate_debug, MptPartialTriePreImages},
        compact_processing_common::{CompactParsingError, CompactParsingResult},
        compact_smt_processing::process_compact_smt_prestate_debug,
    },
    decoding_mpt::{MptTraceParsingError, MptTraceParsingResult},
    decoding_smt::{SmtTraceParsingError, SmtTraceParsingResult},
    processed_block_trace::ProcessedBlockTrace,
    processed_block_trace_mpt::{MptProcessedBlockTracePreImages, ProcessingMeta},
    processed_block_trace_smt::SmtProcessedBlockTracePreImages,
    trace_protocol::{
        BlockTrace, MptBlockTraceTriePreImages, MptCombinedPreImages,
        MptSeparateStorageTriesPreImage, MptSeparateTriePreImage, MptSeparateTriePreImages,
        MptTrieCompact, MptTrieUncompressed, SingleSmtPreImage, SmtBlockTraceTriePreImages,
        TriePreImage,
    },
    types::HashedAccountAddr,
};

const COMPATIBLE_HEADER_VERSION: u8 = 1;

pub type TraceParsingResult<T> = Result<T, TraceParsingError>;

// TODO: Split into two error types based on if `UnexpectedTraceFormat` can
// occur or not...
#[derive(Clone, Debug, Error)]
pub enum TraceParsingError {
    #[error(transparent)]
    Mpt(#[from] Box<MptTraceParsingError>),

    #[error(transparent)]
    Smt(#[from] SmtTraceParsingError),

    #[error(transparent)]
    Compact(#[from] CompactParsingError),

    #[error("Got a trace format that was not expected!")]
    UnexpectedTraceFormat,
}

#[derive(Clone, Debug, EnumAsInner)]
pub enum ProcessedPreImage {
    Mpt(MptProcessedBlockTracePreImages),
    Smt(SmtProcessedBlockTracePreImages),
}

/// Processes any type of pre-image
pub(crate) fn process_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceParsingResult<Box<ProcessedPreImage>> {
    Ok(Box::new(match image {
        TriePreImage::Mpt(images) => ProcessedPreImage::Mpt(process_mpt_trie_images(images)?),
        TriePreImage::Smt(images) => ProcessedPreImage::Smt(process_smt_trie_images(images)?),
    }))
}

/// Process a block trace pre-image compact into an MPT payload. Will return an
/// error if given an SMT payload.
pub(crate) fn process_mpt_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceParsingResult<MptProcessedBlockTracePreImages> {
    let res = process_mpt_trie_images(
        image
            .into_mpt()
            .map_err(|_| TraceParsingError::UnexpectedTraceFormat)?,
    )?;

    Ok(res)
}

/// Process a block trace pre-image compact into an SMT payload. Will return an
/// error if given an MPT payload.
pub(crate) fn process_smt_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceParsingResult<SmtProcessedBlockTracePreImages> {
    let res = process_smt_trie_images(
        image
            .into_smt()
            .map_err(|_| TraceParsingError::UnexpectedTraceFormat)?,
    )?;

    Ok(res)
}

pub(crate) fn process_mpt_trie_images(
    images: MptBlockTraceTriePreImages,
) -> CompactParsingResult<MptProcessedBlockTracePreImages> {
    match images {
        MptBlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images(t),
        MptBlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(
    tries: MptCombinedPreImages,
) -> CompactParsingResult<MptProcessedBlockTracePreImages> {
    process_compact_trie(tries.compact)
}

fn process_separate_trie_pre_images(
    tries: MptSeparateTriePreImages,
) -> CompactParsingResult<MptProcessedBlockTracePreImages> {
    let tries = MptPartialTriePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
    };

    Ok(MptProcessedBlockTracePreImages {
        tries,
        extra_code_hash_mappings: None,
    })
}

fn process_state_trie(trie: MptSeparateTriePreImage) -> HashedPartialTrie {
    match trie {
        MptSeparateTriePreImage::Uncompressed(_) => todo!(),
        MptSeparateTriePreImage::Direct(t) => t.0,
    }
}

fn process_storage_tries(
    trie: MptSeparateStorageTriesPreImage,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    match trie {
        MptSeparateStorageTriesPreImage::SingleTrie(t) => process_single_combined_storage_tries(t),
        MptSeparateStorageTriesPreImage::MultipleTries(t) => process_multiple_storage_tries(t),
    }
}

fn process_single_combined_storage_tries(
    _trie: MptTrieUncompressed,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_multiple_storage_tries(
    _tries: HashMap<HashedAccountAddr, MptSeparateTriePreImage>,
) -> HashMap<HashedAccountAddr, HashedPartialTrie> {
    todo!()
}

fn process_compact_trie(
    trie: MptTrieCompact,
) -> CompactParsingResult<MptProcessedBlockTracePreImages> {
    let out = process_compact_mpt_prestate_debug(trie)?;

    // TODO: Make this into a result...
    assert!(out.header.version_is_compatible(COMPATIBLE_HEADER_VERSION));

    Ok(out.into())
}

fn process_smt_trie_images(
    images: SmtBlockTraceTriePreImages,
) -> CompactParsingResult<SmtProcessedBlockTracePreImages> {
    match images {
        SmtBlockTraceTriePreImages::Single(image) => process_smt_single_trie_image(image),
    }
}

fn process_smt_single_trie_image(
    image: SingleSmtPreImage,
) -> CompactParsingResult<SmtProcessedBlockTracePreImages> {
    let out = process_compact_smt_prestate_debug(image)?;

    // TODO: Make this into a result...
    assert!(out.header.version_is_compatible(COMPATIBLE_HEADER_VERSION));

    Ok(out.into())
}
