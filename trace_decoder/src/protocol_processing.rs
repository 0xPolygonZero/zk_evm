//! Logic to processes the "outer" structure of the protocol payload. All
//! "inner" complex logic (eg. compact decoding) is handled in separate
//! dedicated modules.

use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{Display, Formatter},
};

use enum_as_inner::EnumAsInner;
use mpt_trie::partial_trie::HashedPartialTrie;
use thiserror::Error;

use crate::{
    compact::compact_prestate_processing::{
        process_compact_prestate_debug, CompactDecodingResult, CompactParsingError,
        MptPartialTriePreImages,
    },
    decoding::TraceDecodingError,
    processed_block_trace_mpt::MptProcessedBlockTracePreImages,
    processed_block_trace_smt::SmtProcessedBlockTracePreImage,
    trace_protocol::{
        MptBlockTraceTriePreImages, MptCombinedPreImages, MptSeparateStorageTriesPreImage,
        MptSeparateTriePreImage, MptSeparateTriePreImages, MptTrieCompact, MptTrieUncompressed,
        SingleSmtPreImage, SmtBlockTraceTriePreImages, TriePreImage,
    },
    types::HashedAccountAddr,
};

const COMPATIBLE_HEADER_VERSION: u8 = 1;

/// Result of decoding an incoming block trace.
pub type TraceProtocolDecodingResult<T> = Result<T, TraceProtocolDecodingError>;

/// Error from decoding an incoming block trace.
#[derive(Clone, Debug, Error)]
pub enum TraceProtocolDecodingError {
    /// Error from decoding compact.
    #[error(transparent)]
    CompactDecoding(#[from] CompactParsingError),

    /// Error from decoding traces.
    #[error(transparent)]
    TraceDecoding(#[from] Box<TraceDecodingError>),

    /// Error from compact being in a different format from the one we expected.
    #[error("Got an {found} trace format but expected one in the format of {expected}!")]
    UnexpectedCompactFormat {
        /// The format that we ended up receiving.
        found: CompactFormatType,

        /// The format that we expected to receive.
        expected: CompactFormatType,
    },
}

/// Type to encode the format of compact.
#[derive(Clone, Copy, Debug)]
pub enum CompactFormatType {
    /// MPT compact
    Mpt,

    /// SMT compact
    Smt,
}

impl<T: Borrow<TriePreImage>> From<T> for CompactFormatType {
    fn from(v: T) -> Self {
        match v.borrow() {
            TriePreImage::Mpt(_) => CompactFormatType::Mpt,
            TriePreImage::Smt(_) => CompactFormatType::Smt,
        }
    }
}

impl Display for CompactFormatType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Pre-image data that may be in either an MPT or SMT format.
#[derive(Clone, Debug, EnumAsInner)]
pub enum ProcessedPreImage {
    /// MPT pre-image.
    Mpt(MptProcessedBlockTracePreImages),

    /// SMT pre-image.
    Smt(SmtProcessedBlockTracePreImage),
}

/// Processes any type of pre-image
pub fn process_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceProtocolDecodingResult<Box<ProcessedPreImage>> {
    Ok(Box::new(match image {
        TriePreImage::Mpt(images) => ProcessedPreImage::Mpt(process_mpt_trie_images(images)?),
        TriePreImage::Smt(images) => ProcessedPreImage::Smt(process_smt_trie_images(images)?),
    }))
}

/// Process a block trace pre-image compact into an MPT payload. Will return an
/// error if given an SMT payload.
pub(crate) fn process_mpt_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceProtocolDecodingResult<MptProcessedBlockTracePreImages> {
    let res = process_mpt_trie_images(
        image
            .into_mpt()
            .map_err(|e| handle_unexpected_compact_type_error(e, CompactFormatType::Mpt))?,
    )?;

    Ok(res)
}

/// Process a block trace pre-image compact into an SMT payload. Will return an
/// error if given an MPT payload.
pub fn process_smt_block_trace_trie_pre_images(
    image: TriePreImage,
) -> TraceProtocolDecodingResult<SmtProcessedBlockTracePreImage> {
    let res: SmtProcessedBlockTracePreImage = process_smt_trie_images(
        image
            .into_smt()
            .map_err(|e| handle_unexpected_compact_type_error(e, CompactFormatType::Smt))?,
    )?;

    Ok(res)
}

fn process_mpt_trie_images(
    images: MptBlockTraceTriePreImages,
) -> TraceProtocolDecodingResult<MptProcessedBlockTracePreImages> {
    match images {
        MptBlockTraceTriePreImages::Separate(t) => process_separate_trie_pre_images(t),
        MptBlockTraceTriePreImages::Combined(t) => process_combined_trie_pre_images(t),
    }
}

fn process_combined_trie_pre_images(
    tries: MptCombinedPreImages,
) -> TraceProtocolDecodingResult<MptProcessedBlockTracePreImages> {
    process_compact_trie(tries.compact)
}

fn process_separate_trie_pre_images(
    tries: MptSeparateTriePreImages,
) -> TraceProtocolDecodingResult<MptProcessedBlockTracePreImages> {
    let tries = MptPartialTriePreImages {
        state: process_state_trie(tries.state),
        storage: process_storage_tries(tries.storage),
    };

    Ok(MptProcessedBlockTracePreImages { tries })
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
) -> TraceProtocolDecodingResult<MptProcessedBlockTracePreImages> {
    let out = process_compact_prestate_debug(trie)?;

    if !out.header.version_is_compatible(COMPATIBLE_HEADER_VERSION) {
        return Err(CompactParsingError::IncompatibleVersion(
            COMPATIBLE_HEADER_VERSION,
            out.header.version,
        )
        .into());
    }

    Ok(out.into())
}

fn process_smt_trie_images(
    images: SmtBlockTraceTriePreImages,
) -> CompactDecodingResult<SmtProcessedBlockTracePreImage> {
    match images {
        SmtBlockTraceTriePreImages::Single(image) => process_smt_single_trie_image(image),
    }
}

fn process_smt_single_trie_image(
    _image: SingleSmtPreImage,
) -> CompactDecodingResult<SmtProcessedBlockTracePreImage> {
    todo!()
}

fn handle_unexpected_compact_type_error(
    found: TriePreImage,
    expected: CompactFormatType,
) -> TraceProtocolDecodingError {
    TraceProtocolDecodingError::UnexpectedCompactFormat {
        found: found.into(),
        expected,
    }
}
