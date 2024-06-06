//! Sane parser for witness format.
//!
//! Based on [this specification](*https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout)

use std::{any::type_name, io};

use ethereum_types::U256;
use nunny::NonEmpty;
use serde::de::DeserializeOwned;
use winnow::{
    combinator::{empty, eof, repeat_till, trace},
    error::{ErrMode, ErrorKind, FromExternalError},
    stream::Stream,
    token::{any, literal, take},
    PResult, Parser as _,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Witness {
    pub header: V1Header,
    pub instructions: NonEmpty<Vec<Instruction>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V1Header;

/// Names are taken from the spec.
/// Spec also requires sequences to be non-empty
///
/// CBOR supports unsigned integers up to `2^64 -1`[^1], so that's what we use
/// for native integers.
///
/// [^1]: <https://en.wikipedia.org/wiki/CBOR#Integers_(types_0_and_1)>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Instruction {
    Leaf {
        /// `ENCODE_KEY`-ed
        key: NonEmpty<Vec<u8>>,
        value: NonEmpty<Vec<u8>>,
    },
    // BUG: the spec has `EXTENSION` and `ACCOUNT_LEAF` inconsistent
    // between the instruction list and encoding list
    Extension {
        /// `ENCODE_KEY`-ed
        key: NonEmpty<Vec<u8>>,
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
        /// `ENCODE_KEY`-ed
        key: NonEmpty<Vec<u8>>,
        nonce: Option<u64>,
        // BUG: see decode site
        balance: Option<U256>,
        has_code: bool,
        has_storage: bool,
    },
    NewTrie,
}

/// Parameterise our combinators over the error type to facilitate opt-in
/// debugging.
///
/// Define this trait for conciseness
trait ParserError<'a>:
    winnow::error::ParserError<&'a [u8]>
    + FromExternalError<&'a [u8], ciborium::de::Error<io::Error>>
    + FromExternalError<&'a [u8], UnrecognisedBits>
{
}

impl<'a, E> ParserError<'a> for E where
    E: winnow::error::ParserError<&'a [u8]>
        + FromExternalError<&'a [u8], ciborium::de::Error<io::Error>>
        + FromExternalError<&'a [u8], UnrecognisedBits>
{
}

fn witness<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<Witness, E> {
    Ok(Witness {
        header: header.parse_next(input)?,
        instructions: repeat_till(1.., instruction, eof)
            .map(|(it, _)| NonEmpty::<Vec<_>>::new(it).unwrap())
            .parse_next(input)?,
    })
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
            (cbor, cbor).map(|(key, value)| Instruction::Leaf { key, value }),
        )
        .parse_next(input),
        0x01 => {
            trace("extension", cbor.map(|key| Instruction::Extension { key })).parse_next(input)
        }
        0x02 => trace("branch", cbor.map(|mask| Instruction::Branch { mask })).parse_next(input),
        0x03 => {
            trace("hash", array.map(|raw_hash| Instruction::Hash { raw_hash })).parse_next(input)
        }
        0x04 => {
            trace("code", cbor.map(|raw_code| Instruction::Code { raw_code })).parse_next(input)
        }
        0x05 => trace("account_leaf", account_leaf).parse_next(input),
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
struct UnrecognisedBits;

fn account_leaf<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<Instruction, E> {
    bitflags::bitflags! {
        struct AccountLeafFlags: u8 {
            const HAS_CODE = 0b0000_0001;
            const HAS_STORAGE = 0b0000_0010;
            const ENCODES_NONCE = 0b0000_0100;
            const ENCODES_BALANCE = 0b0000_1000;
        }
    }

    let key = cbor.parse_next(input)?;
    let flags = any
        .try_map(|byte| AccountLeafFlags::from_bits(byte).ok_or(UnrecognisedBits))
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
        has_code: flags.contains(AccountLeafFlags::HAS_CODE),
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
fn cbor_test_vectors() {
    do_test(b"\x00", 0, cbor);
    do_test(b"\x01", 1, cbor);
    do_test(b"\x0a", 10, cbor);
    do_test(b"\x17", 23, cbor);
}

#[cfg(test)]
mod witness_test_vectors {
    use hex_literal::hex;
    type Error = winnow::error::ContextError;

    use super::*;

    #[test]
    fn simple() {
        let src = hex!("01004110443132333400411044313233340218300042035044313233350218180158200000000000000000000000000000000000000000000000000000000000000012");
        dbg!(witness::<Error>.parse(&src).unwrap());
    }

    #[test]
    fn one() {
        let src = hex!("01055821033601462093b5945d1676df093446790fd31b20e7b12a2e8e5e09d068109616b0084a021e19e0c9bab240000005582103468288056310c82aa4c01a7e12a10f8111a0560e72b700555479031b86c357d0084101031a697e814758281972fcd13bc9707dbcd2f195986b05463d7b78426508445a0405582103b70e80538acdabd6137353b0f9d8d149f4dba91e8be2e7946e409bfdbe685b900841010558210389802d6ed1a28b049e9d4fe5334c5902fd9bc00c42821c82f82ee2da10be90800841010558200256274a27dd7524955417c11ecd917251cc7c4c8310f4c7e4bd3c304d3d9a79084a021e19e0c9bab2400000055820023ab0970b73895b8c9959bae685c3a19f45eb5ad89d42b52a340ec4ac204d190841010219102005582103876da518a393dbd067dc72abfa08d475ed6447fca96d92ec3f9e7eba503ca6100841010558210352688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62008410105582103690b239ba3aaf993e443ae14aeffc44cf8d9931a79baed9fa141d0e4506e131008410102196573");
        dbg!(witness::<Error>.parse(&src).unwrap());
    }
}
