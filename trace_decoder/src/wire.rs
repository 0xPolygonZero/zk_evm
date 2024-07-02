//! We support two wire formats:
//! - Type 1, based on [this specification](https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout).
//! - Type 2, loosely based on [this specification](https://github.com/0xPolygonHermez/cdk-erigon/blob/d1d6b3c7a4c81c46fd995c1baa5c1f8069ff0348/turbo/trie/WITNESS.md)
//!
//! Fortunately, their opcodes don't conflict, so we can have a single
//! [`Instruction`] type, with shared parsing logic in this module, and bail on
//! unsupported instructions later on in the frontend.
//!
//! This is fine because we don't care about failing fast when parsing.

use std::{any::type_name, iter};

use anyhow::bail;
use either::Either;
use ethereum_types::U256;
use nunny::NonEmpty;
use serde::de::DeserializeOwned;
use u4::{U4x2, U4};
use winnow::{
    combinator::{empty, eof, fail, preceded, repeat_till, trace},
    error::{ErrorKind, FromExternalError, StrContext},
    stream::Stream,
    token::{any, one_of, take},
    Parser as _,
};

pub fn parse(input: &[u8]) -> anyhow::Result<NonEmpty<Vec<Instruction>>> {
    match preceded(
        one_of((0u8, 1u8)), // header
        repeat_till(1.., instruction, eof).map(|(it, _)| {
            NonEmpty::<Vec<_>>::new(it).expect("repeat_till should ensure non-empty collection")
        }),
    )
    .parse(input)
    {
        Ok(it) => Ok(it),
        Err(e) => bail!("parse error at offset {}: {}", e.offset(), e.inner()),
    }
}

/// Names are taken from the spec.
/// Spec also requires sequences to be non-empty.
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
    /// BUG(spec): `EXTENSION` and `ACCOUNT_LEAF` are inconsistent
    ///            between the instruction list and encoding list
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
        /// BUG(spec): see decode site [`account_leaf`].
        balance: Option<U256>,
        has_code: bool,
        has_storage: bool,
    },
    SmtLeaf(SmtLeaf),
    /// BUG(spec): see parse site [`instruction`].
    EmptyRoot,
    NewTrie,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SmtLeaf {
    pub node_type: SmtLeafType,
    pub address: NonEmpty<Vec<u8>>,
    pub value: NonEmpty<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SmtLeafType {
    Balance,
    Nonce,
    Code,
    Storage(NonEmpty<Vec<u8>>),
    CodeLength,
}

/// A single place to swap out the error type if required.
type PResult<T> = winnow::PResult<T, winnow::error::ContextError>;

fn instruction(input: &mut &[u8]) -> PResult<Instruction> {
    let start = input.checkpoint();
    let opcode = any(input)?;
    // this is [`winnow::combinator::dispatch`] without the macro magic
    match opcode {
        0x00 => trace(
            "leaf",
            (key, cbor).map(|(key, value)| Instruction::Leaf { key, value }),
        )
        .parse_next(input),
        0x01 => trace("extension", key.map(|key| Instruction::Extension { key })).parse_next(input),
        0x02 => trace("branch", cbor.map(|mask| Instruction::Branch { mask })).parse_next(input),
        0x03 => {
            trace("hash", array.map(|raw_hash| Instruction::Hash { raw_hash })).parse_next(input)
        }
        0x04 => {
            trace("code", cbor.map(|raw_code| Instruction::Code { raw_code })).parse_next(input)
        }
        0x05 => trace("account_leaf", account_leaf).parse_next(input),
        // BUG(spec): this opcode is undocumented, but the previous version of
        //            this code had it, and our tests fail without it.
        0x06 => trace("empty_root", empty.value(Instruction::EmptyRoot)).parse_next(input),
        0x07 => trace("smt_leaf", smt_leaf).parse_next(input),
        0xBB => trace("new_trie", empty.value(Instruction::NewTrie)).parse_next(input),
        _ => {
            input.reset(&start);
            fail.context(StrContext::Label("unrecognised opcode"))
                .parse_next(input)
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("{}", .0)]
struct Error(&'static str);

fn account_leaf(input: &mut &[u8]) -> PResult<Instruction> {
    bitflags::bitflags! {
        struct AccountLeafFlags: u8 {
            const HAS_CODE = 0b0000_0001;
            const HAS_STORAGE = 0b0000_0010;
            const ENCODES_NONCE = 0b0000_0100;
            const ENCODES_BALANCE = 0b0000_1000;
        }
    }
    let key = key(input)?;
    let flags = any
        .try_map(|byte| {
            AccountLeafFlags::from_bits(byte)
                .ok_or(Error("unrecognised bits in flags for account leaf"))
        })
        .parse_next(input)?;

    Ok(Instruction::AccountLeaf {
        key,
        nonce: match flags.contains(AccountLeafFlags::ENCODES_NONCE) {
            true => Some(trace("nonce", cbor).parse_next(input)?),
            false => None,
        },
        balance: match flags.contains(AccountLeafFlags::ENCODES_BALANCE) {
            // BUG(spec): the spec says CBOR(balance), where we'd expect CBOR
            //            integer, but actually we read a cbor vec, and decode
            //            that as BE
            true => Some(
                trace(
                    "balance",
                    cbor::<Vec<u8>>.map(|bytes| U256::from_big_endian(&bytes)),
                )
                .parse_next(input)?,
            ),
            false => None,
        },
        has_storage: flags.contains(AccountLeafFlags::HAS_STORAGE),
        has_code: {
            let has_code = flags.contains(AccountLeafFlags::HAS_CODE);
            if has_code {
                // BUG(spec): this field is undocumented, but the previous
                //            version of this code had it, and our tests fail
                //            without it
                trace("code_length", cbor::<u64>).parse_next(input)?;
            }
            has_code
        },
    })
}

fn smt_leaf(input: &mut &[u8]) -> PResult<Instruction> {
    let start = input.checkpoint();
    let node_type = any(input)?;
    Ok(Instruction::SmtLeaf(SmtLeaf {
        address: cbor(input)?,
        node_type: match node_type {
            0 => SmtLeafType::Balance,
            1 => SmtLeafType::Nonce,
            2 => SmtLeafType::Code,
            3 => SmtLeafType::Storage(cbor(input)?),
            4 => SmtLeafType::CodeLength,
            _ => {
                input.reset(&start);
                fail.context(StrContext::Label("unrecognised leaf node type"))
                    .parse_next(input)?
            }
        },
        value: cbor(input)?,
    }))
}

fn key(input: &mut &[u8]) -> PResult<NonEmpty<Vec<U4>>> {
    trace("key", cbor.try_map(|it: NonEmpty<Vec<u8>>| decode_key(&it))).parse_next(input)
}

fn cbor<T: DeserializeOwned + std::fmt::Debug>(input: &mut &[u8]) -> PResult<T> {
    trace(
        format!("cbor{{{}}}", type_name::<T>()),
        |input: &mut &[u8]| {
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

fn decode_key(bytes: &NonEmpty<[u8]>) -> Result<NonEmpty<Vec<U4>>, Error> {
    bitflags::bitflags! {
        struct EncodeKeyFlags: u8 {
            const ODD = 0b0000_0001;
            const TERMINATED = 0b0000_0010;
        }
    }
    let v = match bytes.split_first() {
        // BUG(spec): the previous implementation said that Erigon does this
        (only, &[]) => nunny::vec![U4::new(*only).ok_or(Error("excess bits in single nibble"))?],
        (flags, rest) => {
            // check the flags
            let flags = EncodeKeyFlags::from_bits(*flags)
                .ok_or(Error("unrecognised bits in flags for key encoding"))?;
            // BUG(spec)?: the previous implementation ignored this flag, and
            //             our tests fail without it - perhaps it's &-ed with
            //             the prior U4?
            // if flags.contains(EncodeKeyFlags::TERMINATED) {
            //     match rest.split_last() {
            //         Some((0x10, new_rest)) => rest = new_rest,
            //         _ => return Err(Error("bad terminator for key")),
            //     }
            // }

            // treat the final byte as special...
            let (last, rest) = match rest.split_last() {
                Some((last, rest)) => (Some(*last), rest),
                None => (None, &[][..]),
            };

            // ...according to the ODD flag
            let tail = match (last, flags.contains(EncodeKeyFlags::ODD)) {
                (None, true) => return Err(Error("span was zero but odd flag was set")),
                (None, false) => Either::Left(iter::empty::<U4>()),
                (Some(left), true) => Either::Right(Either::Left(iter::once(
                    U4::new(left.rotate_right(4)).ok_or(Error("unrecognised bits in nibble"))?,
                ))),
                (Some(packed), false) => {
                    let both = U4x2 { packed };
                    Either::Right(Either::Right([both.left(), both.right()].into_iter()))
                }
            };

            // parse the rest of the bytes as nibbles
            nunny::Vec::new(
                rest.iter()
                    .copied()
                    .flat_map(|packed| {
                        let both = U4x2 { packed };
                        [both.left(), both.right()]
                    })
                    .chain(tail)
                    .collect(),
            )
            .expect("an empty `rest` must be caught by the Erigon special case")
        }
    };
    Ok(v)
}

fn array<const N: usize>(input: &mut &[u8]) -> PResult<[u8; N]> {
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
