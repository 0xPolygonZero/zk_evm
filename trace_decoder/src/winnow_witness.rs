//! Sane parser for witness format.
//!
//! Based on [this specification](*https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout)

use std::{any::type_name, io, mem::size_of};

use ethereum_types::U256;
use keccak_hash::H256;
use mpt_trie_type_1::nibbles::Nibbles;
use serde::de::DeserializeOwned;
use winnow::{
    combinator::{alt, empty, eof, preceded, repeat_till, trace},
    error::{ErrMode, ErrorKind, FromExternalError, TreeError},
    stream::Stream,
    token::{any, literal, take},
    PResult, Parser as _,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Witness {
    pub header: V1Header,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V1Header;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Instruction {
    Leaf {
        key: Nibbles,
        value: Vec<u8>,
    },
    Extension(Nibbles),
    Branch {
        mask: u32,
    },
    Hash(H256),
    Code(Vec<u8>),
    AccountLeaf {
        key: Nibbles,
        nonce: Option<U256>,
        balance: Option<U256>,
        // according to the spec, this should be `has_code: bool`,
        // but in actuality, there's an additional field here.
        code_size: Option<u64>,
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
        instructions: repeat_till(.., instruction, eof)
            .map(|(it, _)| it)
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
            (key, cbor).map(|(key, value)| Instruction::Leaf { key, value }),
        )
        .parse_next(input),
        0x01 => trace("extension", key.map(Instruction::Extension)).parse_next(input),
        0x02 => trace("branch", cbor.map(|mask| Instruction::Branch { mask })).parse_next(input),
        0x03 => trace("hash", h256.map(Instruction::Hash)).parse_next(input),
        0x04 => trace("code", cbor.map(Instruction::Code)).parse_next(input),
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

    let key = key.parse_next(input)?;
    let flags = any
        .try_map(|byte| AccountLeafFlags::from_bits(byte).ok_or(UnrecognisedBits))
        .parse_next(input)?;

    Ok(Instruction::AccountLeaf {
        key,
        nonce: match flags.contains(AccountLeafFlags::ENCODES_NONCE) {
            true => Some(trace("nonce", u256).parse_next(input)?),
            false => None,
        },
        balance: match flags.contains(AccountLeafFlags::ENCODES_BALANCE) {
            true => Some(trace("balance", u256).parse_next(input)?),
            false => None,
        },
        // TODO(0xaatif): brendan's code deviates from the spec and reads a u64 if HAS_CODE
        code_size: match flags.contains(AccountLeafFlags::HAS_CODE) {
            true => Some((trace("code_size", cbor)).parse_next(input)?),
            false => None,
        },
        has_storage: flags.contains(AccountLeafFlags::HAS_STORAGE),
    })
}

fn cbor<'a, T: DeserializeOwned, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<T, E> {
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

fn key<'a, E>(input: &mut &'a [u8]) -> PResult<Nibbles, E>
where
    E: ParserError<'a> + FromExternalError<&'a [u8], ciborium::de::Error<io::Error>>,
{
    trace(
        "key",
        cbor::<Vec<u8>, _>.map(|bytes| {
            let mut key = Nibbles::default();

            if bytes.is_empty() {
                return key;
            }

            // I have no idea why Erigon is doing this with their keys, as I'm don't think
            // this is part of the yellow paper at all?
            if bytes.len() == 1 {
                let low_nib = bytes[0] & 0b00001111;
                key.push_nibble_back(low_nib);
            }

            let flags = bytes[0];
            let is_odd = (flags & 0b00000001) != 0;
            let has_term = (flags & 0b00000010) != 0;

            // ... Term bit seems to have no effect on the key?
            let actual_key_bytes = match has_term {
                false => &bytes[1..],
                true => &bytes[1..],
            };

            if actual_key_bytes.is_empty() {
                return key;
            }

            let final_byte_idx = actual_key_bytes.len() - 1;

            // The compact key format is kind of weird. We need to read the nibbles
            // backwards from how we expect it internally.
            for byte in &actual_key_bytes[..(final_byte_idx)] {
                let high_nib = (byte & 0b11110000) >> 4;
                let low_nib = byte & 0b00001111;

                key.push_nibble_back(high_nib);
                key.push_nibble_back(low_nib);
            }

            // The final byte we might need to ignore the last nibble, so we need to do it
            // separately.
            let final_byte = actual_key_bytes[final_byte_idx];
            let high_nib = (final_byte & 0b11110000) >> 4;
            key.push_nibble_back(high_nib);

            if !is_odd {
                let low_nib = final_byte & 0b00001111;
                key.push_nibble_back(low_nib);
            }

            key
        }),
    )
    .parse_next(input)
}

fn h256<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<H256, E> {
    array.map(H256).parse_next(input)
}

fn u256<'a, E: ParserError<'a>>(input: &mut &'a [u8]) -> PResult<U256, E> {
    array::<{ size_of::<U256>() }, _>
        .map(|it| U256::from_big_endian(&it))
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

#[test]
fn witness_test_vectors() {
    use hex_literal::hex;
    use winnow::error::TreeError;

    let simple = hex!("01004110443132333400411044313233340218300042035044313233350218180158200000000000000000000000000000000000000000000000000000000000000012");
    dbg!(witness::<TreeError<_>>.parse(&simple)).unwrap();
}
