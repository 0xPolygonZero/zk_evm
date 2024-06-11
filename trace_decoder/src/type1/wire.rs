use std::{any::type_name, io, iter};

use anyhow::bail;
use either::Either;
use ethereum_types::U256;
use nunny::NonEmpty;
use serde::de::DeserializeOwned;
use winnow::{
    combinator::{empty, eof, preceded, repeat_till, trace},
    error::{ErrMode, ErrorKind, FromExternalError},
    stream::Stream,
    token::{any, literal, take},
    PResult, Parser as _,
};

use super::u4::U4;
use crate::type1::u4::U4x2;

pub fn parse(input: &[u8]) -> anyhow::Result<NonEmpty<Vec<Instruction>>> {
    match preceded(
        header::<winnow::error::ContextError>,
        repeat_till(1.., instruction, eof).map(|(it, _)| {
            NonEmpty::<Vec<_>>::new(it).expect("repeat_till should ensure non-empty collection")
        }),
    )
    .parse(input)
    {
        Ok(it) => Ok(it),
        Err(e) => bail!("parse error: {}", e),
    }
}

/// Names are taken from the spec.
/// Spec also requires sequences to be non-empty
///
/// CBOR supports unsigned integers up to `2^64 -1`[^1], so we use [`u64`]
/// for directly read integers.
///
/// [^1]: <https://en.wikipedia.org/wiki/CBOR#Integers_(types_0_and_1)>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Instruction {
    Leaf {
        key: NonEmpty<Vec<U4>>,
        value: NonEmpty<Vec<u8>>,
    },
    // BUG: the spec has `EXTENSION` and `ACCOUNT_LEAF` inconsistent
    // between the instruction list and encoding list
    Extension {
        key: NonEmpty<Vec<U4>>,
    },
    Branch {
        mask: u64,
    },
    Hash {
        raw_hash: [u8; 32],
    },
    Code {
        raw_code: NonEmpty<Vec<u8>>,
    },
    AccountLeaf {
        key: NonEmpty<Vec<U4>>,
        nonce: Option<u64>,
        // BUG: see decode site
        balance: Option<U256>,
        has_code: bool,
        has_storage: bool,
    },
    // BUG: see parse site
    EmptyRoot,
    NewTrie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct V1Header;

/// Parameterise our combinators over the error type to facilitate opt-in
/// debugging.
///
/// Define this trait for conciseness
trait ParserError<'a>:
    winnow::error::ParserError<&'a [u8]>
    + FromExternalError<&'a [u8], ciborium::de::Error<io::Error>>
    + FromExternalError<&'a [u8], UnrecognisedAccountLeafFlags>
    + FromExternalError<&'a [u8], DecodeKeyError>
{
}

impl<'a, E> ParserError<'a> for E where
    E: winnow::error::ParserError<&'a [u8]>
        + FromExternalError<&'a [u8], ciborium::de::Error<io::Error>>
        + FromExternalError<&'a [u8], UnrecognisedAccountLeafFlags>
        + FromExternalError<&'a [u8], DecodeKeyError>
{
}

fn header<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<V1Header, E> {
    trace("header", literal(1).value(V1Header)).parse_next(input)
}

fn instruction<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<Instruction, E> {
    let start = input.checkpoint();
    let opcode = any.parse_next(input)?;
    // I don't like the `winnow::combinator::dispatch!` macro
    match opcode {
        0x00 => trace(
            "leaf",
            (cbor.try_map(|it: NonEmpty<Vec<u8>>| decode_key(&it)), cbor)
                .map(|(key, value)| Instruction::Leaf { key, value }),
        )
        .parse_next(input),
        0x01 => trace(
            "extension",
            cbor.try_map(|it: NonEmpty<Vec<u8>>| decode_key(&it))
                .map(|key| Instruction::Extension { key }),
        )
        .parse_next(input),
        0x02 => trace("branch", cbor.map(|mask| Instruction::Branch { mask })).parse_next(input),
        0x03 => {
            trace("hash", array.map(|raw_hash| Instruction::Hash { raw_hash })).parse_next(input)
        }
        0x04 => {
            trace("code", cbor.map(|raw_code| Instruction::Code { raw_code })).parse_next(input)
        }
        0x05 => trace("account_leaf", account_leaf).parse_next(input),
        // BUG: this opcode is is undocumented, but the previous version of
        //      this code had it, and our tests fail without it
        0x06 => trace("empty_root", empty.value(Instruction::EmptyRoot)).parse_next(input),
        0xBB => trace("new_trie", empty.value(Instruction::NewTrie)).parse_next(input),
        _ => {
            input.reset(&start);
            Err(ErrMode::Backtrack(E::from_error_kind(
                input,
                ErrorKind::Alt,
            )))
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("unrecognised bits in flags for account leaf")]
struct UnrecognisedAccountLeafFlags;

fn account_leaf<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<Instruction, E> {
    bitflags::bitflags! {
        struct AccountLeafFlags: u8 {
            const HAS_CODE = 0b0000_0001;
            const HAS_STORAGE = 0b0000_0010;
            const ENCODES_NONCE = 0b0000_0100;
            const ENCODES_BALANCE = 0b0000_1000;
        }
    }

    let key = cbor
        .try_map(|it: NonEmpty<Vec<u8>>| decode_key(&it))
        .parse_next(input)?;
    let flags = any
        .try_map(|byte| AccountLeafFlags::from_bits(byte).ok_or(UnrecognisedAccountLeafFlags))
        .parse_next(input)?;

    Ok(Instruction::AccountLeaf {
        key,
        nonce: match flags.contains(AccountLeafFlags::ENCODES_NONCE) {
            true => Some(trace("nonce", cbor).parse_next(input)?),
            false => None,
        },
        balance: match flags.contains(AccountLeafFlags::ENCODES_BALANCE) {
            // BUG: the spec says CBOR(balance), where we'd expect CBOR integer,
            //      but actually we read a cbor vec, and decode that as BE
            true => Some(
                trace(
                    "balance",
                    cbor::<Vec<u8>, _>.map(|bytes| U256::from_big_endian(&bytes)),
                )
                .parse_next(input)?,
            ),
            false => None,
        },
        has_storage: flags.contains(AccountLeafFlags::HAS_STORAGE),
        has_code: {
            let has_code = flags.contains(AccountLeafFlags::HAS_CODE);
            if has_code {
                // BUG: this field is undocumented, but the previous version of
                //      this code had it, and our tests fail without it
                trace("code_length", cbor::<u64, _>).parse_next(input)?;
            }
            has_code
        },
    })
}

fn cbor<'a, T: DeserializeOwned + std::fmt::Debug, E: ParserError<'a>>(
    input: &mut &'a [u8],
) -> PResult<T, E> {
    trace(
        format!("cbor{{{}}}", type_name::<T>()),
        |input: &mut &'a [u8]| {
            let start = input.checkpoint();
            match ciborium::from_reader::<T, _>(&mut *input) {
                Ok(it) => Ok(it),
                Err(e) => {
                    input.reset(&start);
                    Err(FromExternalError::from_external_error(
                        input,
                        ErrorKind::Verify,
                        e,
                    ))
                }
            }
        },
    )
    .parse_next(input)
}

#[derive(thiserror::Error, Debug)]
enum DecodeKeyError {
    #[error("unrecognised bits in nibble")]
    ExcessNibbleBits,
    #[error("unrecognised bits in flags for key encoding")]
    UnrecognisedKeyFlags,
    // BUG: see commented out code below
    // #[error("missing or invalid terminator for nibbles")]
    // Terminator,
    #[error("span was zero but odd flag was set")]
    OddZero,
}

fn decode_key(bytes: &NonEmpty<[u8]>) -> Result<NonEmpty<Vec<U4>>, DecodeKeyError> {
    bitflags::bitflags! {
        struct EncodeKeyFlags: u8 {
            const ODD = 0b0000_0001;
            const TERMINATED = 0b0000_0010;
        }
    }

    match bytes.split_first() {
        // BUG: the previous implementation said that Erigon does this
        (only, &[]) => Ok(nunny::vec![
            // U4::new(*only).ok_or(DecodeKeyError::ExcessNibbleBits)?
            // TODO(0xaatif): I don't like this line - I'm adding it because
            //                it's required by the simplest test vector
            U4::new(*only).unwrap_or_default()
        ]),
        (flags, /* mut */ rest) => {
            // check the flags
            let flags =
                EncodeKeyFlags::from_bits(*flags).ok_or(DecodeKeyError::UnrecognisedKeyFlags)?;
            // BUG?: the previous implementation ignored this flag - perhaps it's
            //       &-ed with the prior U4?
            // if flags.contains(EncodeKeyFlags::TERMINATED) {
            //     match rest.split_last() {
            //         Some((0x10, new_rest)) => rest = new_rest,
            //         _ => return Err(DecodeKeyError::Terminator),
            //     }
            // }

            // treat the final byte as special...
            let (last, rest) = match rest.split_last() {
                Some((last, rest)) => (Some(*last), rest),
                None => (None, &[][..]),
            };

            // ...according to the ODD flag
            let tail = match (last, flags.contains(EncodeKeyFlags::ODD)) {
                (None, true) => return Err(DecodeKeyError::OddZero),
                (None, false) => Either::Left(iter::empty::<U4>()),
                (Some(left), true) => Either::Right(Either::Left(iter::once(
                    U4::new(left.rotate_right(4)).ok_or(DecodeKeyError::ExcessNibbleBits)?,
                ))),
                (Some(packed), false) => {
                    let both = U4x2 { packed };
                    Either::Right(Either::Right([both.left(), both.right()].into_iter()))
                }
            };

            // parse the rest of the bytes as nibbles
            Ok(nunny::Vec::new(
                rest.iter()
                    .copied()
                    .flat_map(|packed| {
                        let both = U4x2 { packed };
                        [both.left(), both.right()]
                    })
                    .chain(tail)
                    .collect(),
            )
            .expect("an empty `rest` must be caught by the Erigon special case"))
        }
    }
}

fn array<'a, const N: usize, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<[u8; N], E> {
    take(N)
        .map(|it: &[u8]| it.try_into().expect("take has already selected N bytes"))
        .parse_next(input)
}

#[cfg(test)]
#[track_caller]
fn do_test<'a, T: PartialEq + core::fmt::Debug>(
    src: &'a [u8],
    expected: T,
    mut parser: impl winnow::Parser<&'a [u8], T, winnow::error::ContextError>,
) {
    let actual = parser.parse(src.as_ref()).unwrap();
    assert_eq!(expected, actual)
}

/// <https://github.com/cbor/test-vectors/blob/aba89b653e484bc8573c22f3ff35641d79dfd8c1/appendix_a.json>
#[test]
fn cbor_test_cases() {
    do_test(b"\x00", 0, cbor);
    do_test(b"\x01", 1, cbor);
    do_test(b"\x0a", 10, cbor);
    do_test(b"\x17", 23, cbor);
}
