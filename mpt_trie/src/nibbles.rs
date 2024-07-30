#![allow(clippy::assign_op_pattern)]

//! Define [`Nibbles`] and how to convert bytes, hex prefix encodings and
//! strings into nibbles.
use std::mem::size_of;
use std::{
    fmt::{self, Debug},
    iter::once,
};
use std::{
    fmt::{Display, LowerHex, UpperHex},
    ops::Range,
    str::FromStr,
};

use bytes::{Bytes, BytesMut};
use ethereum_types::{H256, U128, U256};
use impl_codec::impl_uint_codec;
use impl_num_traits::impl_uint_num_traits;
use impl_rlp::impl_uint_rlp;
use impl_serde::impl_uint_serde;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uint::construct_uint;
use uint::FromHexError;

use crate::utils::{create_mask_of_1s, is_even};

// Use a whole byte for a Nibble just for convenience
/// A Nibble has 4 bits and is stored as `u8`.
pub type Nibble = u8;

construct_uint! {
    /// Used for the internal representation of a sequence of nibbles.
    /// The choice of [u64; 5] accommodates the 260-bit key requirement efficiently by
    /// leveraging 64-bit instructions for performance, while providing an additional u64
    /// to handle the overflow case beyond the 256-bit capacity of [u64; 4].
    pub struct NibblesIntern(5);
}

impl_uint_num_traits!(NibblesIntern, 5);
impl_uint_serde!(NibblesIntern, 5);
impl_uint_codec!(NibblesIntern, 5);
impl_uint_rlp!(NibblesIntern, 5);

const MULTIPLE_NIBBLES_APPEND_ASSERT_ERR_MSG: &str =
    "Attempted to create a nibbles sequence longer than 64!";
const SINGLE_NIBBLE_APPEND_ASSERT_ERR_MSG: &str =
    "Attempted to append a single nibble that was greater than 15!";

/// Because there are two different ways to convert to `Nibbles`, we don't want
/// to rely on `From`. Instead, we'll define a new trait that defines both
/// conversions.
pub trait ToNibbles {
    /// Convert the type to a sequence of nibbles.
    ///
    /// Note that this will create `Nibbles` with a `Nibble` count that is
    /// accurate down to the nibble. For example, passing in `0x123` has `3`
    /// `Nibble`s and is not padded to the nearest byte (in which case it
    /// would have `4` `Nibble`s).
    fn to_nibbles(self) -> Nibbles;

    /// Convert the type to a sequence of nibbles but pad to the nearest byte.
    fn to_nibbles_byte_padded(self) -> Nibbles
    where
        Self: Sized,
    {
        let mut nibbles = self.to_nibbles();
        nibbles.count = ((nibbles.count + 1) / 2) * 2;

        nibbles
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Hash)]
/// Errors encountered when converting from `Bytes` to `Nibbles`.
pub enum BytesToNibblesError {
    #[error("Tried constructing `Nibbles` from a zero byte slice")]
    /// The size is zero.
    ZeroSizedKey,

    #[error("Tried constructing `Nibbles` from a byte slice with more than 33 bytes (len: {0})")]
    /// The slice is too large.
    TooManyBytes(usize),
}

#[derive(Clone, Debug, Eq, Error, PartialEq, Hash)]
/// Errors encountered when converting to hex prefix encoding to nibbles.
pub enum FromHexPrefixError {
    #[error("Tried to convert a hex prefix byte string into `Nibbles` with invalid flags at the start: {0:#04b}")]
    /// The hex prefix encoding flag is invalid.
    InvalidFlags(Nibble),

    #[error("Tried to convert a hex prefix byte string into `Nibbles` that was longer than 40 bytes: (length: {0}, bytes: {1})")]
    /// The hex prefix encoding is too large.
    TooLong(String, usize),
}

/// Error type for conversion.
#[derive(Clone, Debug, Eq, Error, PartialEq, Hash)]
pub enum NibblesToTypeError {
    #[error("Overflow encountered when converting to U256: {0}")]
    /// Overflow encountered.
    Overflow(NibblesIntern),
}

trait AsU64s {
    fn as_u64s(&self) -> impl Iterator<Item = u64> + '_;
}

macro_rules! impl_as_u64s_for_primitive {
    ($type:ty) => {
        impl AsU64s for $type {
            fn as_u64s(&self) -> impl Iterator<Item = u64> + '_ {
                std::iter::once(*self as u64)
            }
        }
    };
}

impl_as_u64s_for_primitive!(usize);
impl_as_u64s_for_primitive!(u8);
impl_as_u64s_for_primitive!(u16);
impl_as_u64s_for_primitive!(u32);
impl_as_u64s_for_primitive!(u64);

impl AsU64s for U128 {
    fn as_u64s(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }
}

impl AsU64s for U256 {
    fn as_u64s(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }
}

impl AsU64s for NibblesIntern {
    fn as_u64s(&self) -> impl Iterator<Item = u64> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Debug, Error)]
#[error(transparent)]
/// An error encountered when converting a string to a sequence of nibbles.
pub struct StrToNibblesError(#[from] FromHexError);

/// The default conversion to nibbles will be to be precise down to the
/// `Nibble`.
impl<T> From<T> for Nibbles
where
    T: ToNibbles,
{
    fn from(v: T) -> Self {
        v.to_nibbles()
    }
}

macro_rules! impl_to_nibbles {
    ($type:ty) => {
        impl ToNibbles for $type {
            fn to_nibbles(self) -> Nibbles {
                // Ethereum types don't have `BITS` defined.
                #[allow(clippy::manual_bits)]
                let size_bits = size_of::<Self>() * 8;
                let count = (size_bits - self.leading_zeros() as usize + 3) / 4;
                let mut packed = NibblesIntern::zero();

                let parts = self.as_u64s();
                for (i, part) in parts.enumerate().take(packed.0.len()) {
                    packed.0[i] = part;
                }

                Nibbles { count, packed }
            }
        }
    };
}

impl_to_nibbles!(usize);
impl_to_nibbles!(u8);
impl_to_nibbles!(u16);
impl_to_nibbles!(u32);
impl_to_nibbles!(u64);
impl_to_nibbles!(U128);
impl_to_nibbles!(U256);
impl_to_nibbles!(NibblesIntern);

impl<'a> TryFrom<&'a Nibbles> for U256 {
    type Error = NibblesToTypeError;

    fn try_from(value: &'a Nibbles) -> Result<U256, NibblesToTypeError> {
        let NibblesIntern(ref arr) = value.packed;
        if arr[4] != 0 {
            return Err(NibblesToTypeError::Overflow(value.packed));
        }

        let ret = [arr[0], arr[1], arr[2], arr[3]];
        Ok(U256(ret))
    }
}

impl<'a> TryFrom<&'a NibblesIntern> for U256 {
    type Error = NibblesToTypeError;

    fn try_from(value: &'a NibblesIntern) -> Result<U256, NibblesToTypeError> {
        if value.0[4] != 0 {
            return Err(NibblesToTypeError::Overflow(*value));
        }

        let ret = [value.0[0], value.0[1], value.0[2], value.0[3]];
        Ok(U256(ret))
    }
}

impl TryInto<U256> for Nibbles {
    type Error = NibblesToTypeError;

    fn try_into(self) -> Result<U256, NibblesToTypeError> {
        let arr = self.packed;
        if arr.0[4] != 0 {
            return Err(NibblesToTypeError::Overflow(arr));
        }

        let ret = [arr.0[0], arr.0[1], arr.0[2], arr.0[3]];
        Ok(U256(ret))
    }
}

impl From<Nibbles> for H256 {
    fn from(val: Nibbles) -> Self {
        let mut nib_bytes = val.bytes_be();
        if nib_bytes.len() < 32 {
            for _ in nib_bytes.len()..32 {
                nib_bytes.insert(0, 0);
            }
        }

        H256::from_slice(&nib_bytes)
    }
}

impl From<U256> for NibblesIntern {
    fn from(val: U256) -> Self {
        let arr = val.as_u64s();

        let mut ret = NibblesIntern::zero();
        for (i, part) in arr.enumerate() {
            ret.0[i] = part;
        }
        ret
    }
}

#[derive(Copy, Clone, Deserialize, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
/// A sequence of nibbles which is used as the key type into
/// [`PartialTrie`][`crate::partial_trie::PartialTrie`].
///
/// Generally, if you're constructing keys from actual trie data, you probably
/// will be working with `U256`s and `H256`s both of which `Nibbles` has a
/// `From` implementation for.
///
/// It's important to note that leading `0` bits are part of a key. For example:
/// ```rust
/// # use mpt_trie::nibbles::Nibbles;
/// # use std::str::FromStr;
/// let n1 = Nibbles::from_str("0x123").unwrap();
/// let n2 = Nibbles::from_str("0x0123").unwrap();
///
/// assert_ne!(n1, n2); // These are different keys
/// ```
/// Also note by default, converting to `Nibbles` does not pad to the
/// nearest byte like other trie libraries generally do. If you need this
/// behavior, you can construct `Nibbles` like this:
/// ```rust
/// # use mpt_trie::nibbles::ToNibbles;
///
/// let padded = 0x123_u64.to_nibbles_byte_padded();
/// assert_eq!(format!("{:x}", padded), "0x0123");
/// ```
///
/// Note that for the time being, `Nibbles` is limited to key lengths no longer
/// than `256` bits. While we could support arbitrarily long keys, tries in
/// Ethereum never have keys longer than `256` bits. Because of this, we decided
/// to create a minor optimization by restricting max key sizes to `256` bits.
///
/// Finally, note that due to the limitations initializing from an integer, when
/// creating a key directly from an integer, there is no way to know if a
/// leading `0` was passed in.
/// ```rust
/// # use mpt_trie::nibbles::Nibbles;
///
/// let n1 = Nibbles::from(0x123_u64);
/// let n2 = Nibbles::from(0x00000000123_u64); // Use `from_str` or construct `Nibbles` explicitly instead here.
///
/// assert_eq!(n1, n2);
/// assert!(Nibbles::from(0x00000000_u64).is_empty());
/// ```
pub struct Nibbles {
    /// The number of nibbles in this sequence.
    pub count: usize,
    /// A packed encoding of these nibbles. Only the first (least significant)
    /// `4 * count` bits are used. The rest are unused and should be zero.
    pub packed: NibblesIntern,
}

impl Display for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // By default, just use lower hex.
        <Self as LowerHex>::fmt(self, f)
    }
}

// Manual impl in order to print `packed` nicely.
impl Debug for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nibbles")
            .field("count", &self.count)
            .field("packed", &format!("{self:x}"))
            .finish()
    }
}

impl FromStr for Nibbles {
    type Err = StrToNibblesError;

    /// Parses a hex string with or without a preceding "0x".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped_str = s.strip_prefix("0x").unwrap_or(s);
        let leading_zeros = stripped_str
            .chars()
            .position(|c| c != '0')
            .unwrap_or(stripped_str.len());
        let packed = NibblesIntern::from_str(s)?;

        Ok(Self {
            count: leading_zeros + Self::get_num_nibbles_in_key(&packed),
            packed, // TODO: Remove this hack...
        })
    }
}

impl LowerHex for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_hex_str(|bytes| hex::encode(bytes)))
    }
}

impl UpperHex for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_hex_str(|bytes| hex::encode_upper(bytes)))
    }
}

impl Nibbles {
    /// Creates `Nibbles` from big endian bytes.
    ///
    /// Returns an error if the byte slice is empty or is longer than `32`
    /// bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> Result<Self, BytesToNibblesError> {
        Self::from_bytes(bytes, NibblesIntern::from_big_endian)
    }

    /// Creates `Nibbles` from little endian bytes.
    ///
    /// Returns an error if the byte slice is empty or is longer than `32`
    /// bytes.
    pub fn from_bytes_le(bytes: &[u8]) -> Result<Self, BytesToNibblesError> {
        Self::from_bytes(bytes, NibblesIntern::from_little_endian)
    }

    fn from_bytes<F>(bytes: &[u8], conv_f: F) -> Result<Self, BytesToNibblesError>
    where
        F: FnOnce(&[u8]) -> NibblesIntern,
    {
        if bytes.is_empty() {
            return Err(BytesToNibblesError::ZeroSizedKey);
        }

        if bytes.len() > 33 {
            return Err(BytesToNibblesError::TooManyBytes(bytes.len()));
        }

        let packed = conv_f(bytes);

        Ok(Self {
            count: bytes.len() * 2,
            packed,
        })
    }

    /// Creates a new `Nibbles` from a single `Nibble`.
    ///
    /// # Panics
    /// Panics if the nibble is > `0xf`.
    pub fn from_nibble(n: Nibble) -> Self {
        assert!(n <= 0xf);

        Self {
            count: 1,
            packed: n.into(),
        }
    }

    /// Gets the nth proceeding nibble. The front `Nibble` is at idx `0`.
    ///
    /// # Panics
    /// Panics if `idx` is out of range.
    pub fn get_nibble(&self, idx: usize) -> Nibble {
        let nib_idx = self.count - idx - 1;
        let byte = self.packed.byte(nib_idx / 2);

        match is_even(nib_idx) {
            false => (byte & 0b11110000) >> 4,
            true => byte & 0b00001111,
        }
    }

    /// Pops the nibble at the front (the next nibble).
    ///
    /// # Panics
    /// Panics if the `Nibbles` is empty.
    pub fn pop_next_nibble_front(&mut self) -> Nibble {
        let n = self.get_nibble(0);
        self.truncate_n_nibbles_front_mut(1);

        n
    }

    /// Pops the nibble at the back (the last nibble).
    ///
    /// # Panics
    /// Panics if the `Nibbles` is empty.
    pub fn pop_next_nibble_back(&mut self) -> Nibble {
        let n = self.get_nibble(self.count - 1);
        self.truncate_n_nibbles_back_mut(1);

        n
    }

    /// Gets the next `n` nibbles.
    /// # Panics
    /// Panics if `n` is larger than the number of nibbles contained.
    pub fn get_next_nibbles(&self, n: usize) -> Nibbles {
        self.get_nibble_range(0..n)
    }

    /// Pops the next `n` nibbles from the front.
    ///
    /// # Panics
    /// Panics if `n` is larger than the number of nibbles contained.
    pub fn pop_nibbles_front(&mut self, n: usize) -> Nibbles {
        let r = self.get_nibble_range(0..n);
        self.truncate_n_nibbles_front_mut(n);

        r
    }

    /// Pops the next `n` nibbles from the back.
    ///
    /// # Panics
    /// Panics if `n` is larger than the number of nibbles contained.
    pub fn pop_nibbles_back(&mut self, n: usize) -> Nibbles {
        let r = self
            .get_nibble_range((self.count - n)..self.count)
            .reverse();
        self.truncate_n_nibbles_back_mut(n);

        r
    }

    /// Pushes a nibble to the front.
    ///
    /// # Panics
    /// Panics if appending the `Nibble` causes an overflow (total nibbles >
    /// 64).
    pub fn push_nibble_front(&mut self, n: Nibble) {
        self.nibble_append_safety_asserts(n);

        let shift_amt = 4 * self.count;

        self.count += 1;
        self.packed |= NibblesIntern::from(n) << shift_amt;
    }

    /// Pushes a nibble to the back.
    ///
    /// # Panics
    /// Panics if appending the `Nibble` causes an overflow (total nibbles >
    /// 64).
    pub fn push_nibble_back(&mut self, n: Nibble) {
        self.nibble_append_safety_asserts(n);

        self.count += 1;
        self.packed = (self.packed << 4) | n.into();
    }

    /// Appends `Nibbles` to the front.
    ///
    /// # Panics
    /// Panics if appending the `Nibbles` causes an overflow (total nibbles >
    /// 64).
    pub fn push_nibbles_front(&mut self, n: &Self) {
        let new_count = self.count + n.count;
        self.nibbles_append_safety_asserts(new_count);

        let shift_amt = 4 * self.count;

        self.count = new_count;
        self.packed |= n.packed << shift_amt;
    }

    /// Appends `Nibbles` to the back.
    ///
    /// # Panics
    /// Panics if appending the `Nibbles` causes an overflow (total nibbles >
    /// 64).
    pub fn push_nibbles_back(&mut self, n: &Self) {
        let new_count = self.count + n.count;
        self.nibbles_append_safety_asserts(new_count);

        let shift_amt = 4 * n.count;

        self.count = new_count;
        self.packed = (self.packed << shift_amt) | n.packed;
    }

    /// Gets the nibbles at the range specified, where `0` is the next nibble.
    ///
    /// # Panics
    /// Panics if `range.end` is outside of the current `Nibbles`.
    pub fn get_nibble_range(&self, range: Range<usize>) -> Nibbles {
        let range_count = range.end - range.start;

        let shift_amt = (self.count - range.end) * 4;
        let mask = create_mask_of_1s(range_count * 4) << shift_amt;
        let range_packed = (self.packed & mask) >> shift_amt;

        Self {
            count: range_count,
            packed: range_packed,
        }
    }

    /// Drops the next `n` proceeding nibbles without mutation.
    ///
    /// If we truncate more nibbles that there are, we will just return the
    /// `empty` nibble.
    pub fn truncate_n_nibbles_front(&self, n: usize) -> Nibbles {
        let mut nib = *self;
        nib.truncate_n_nibbles_front_mut(n);

        nib
    }

    /// Drops the last `n` nibbles without mutation.
    ///
    /// If we truncate more nibbles that there are, we will just return the
    /// `empty` nibble.
    pub fn truncate_n_nibbles_back(&self, n: usize) -> Nibbles {
        let mut nib = *self;
        nib.truncate_n_nibbles_back_mut(n);

        nib
    }

    /// Drop the next `n` proceeding nibbles.
    ///
    /// If we truncate more nibbles that there are, we will just return the
    /// `empty` nibble.
    pub fn truncate_n_nibbles_front_mut(&mut self, n: usize) {
        let n = self.get_min_truncate_amount_to_prevent_over_truncating(n);

        let mask_shift = (self.count - n) * 4;
        let truncate_mask = !(create_mask_of_1s(n * 4) << mask_shift);

        self.count -= n;
        self.packed &= truncate_mask;
    }

    /// Drop the last `n` nibbles.
    ///
    /// If we truncate more nibbles that there are, we will just return the
    /// `empty` nibble.
    pub fn truncate_n_nibbles_back_mut(&mut self, n: usize) {
        let n = self.get_min_truncate_amount_to_prevent_over_truncating(n);

        let shift_amt = n * 4;
        let truncate_mask = !create_mask_of_1s(n * 4);

        self.count -= n;
        self.packed = (self.packed & truncate_mask) >> shift_amt;
    }

    const fn get_min_truncate_amount_to_prevent_over_truncating(&self, n: usize) -> usize {
        match self.count >= n {
            false => self.count,
            true => n,
        }
    }

    /// Returns whether or not this `Nibbles` contains actual nibbles. (If
    /// `count` is set to `0`)
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Checks if two given `Nibbles` are identical up to the shorter of the two
    /// `Nibbles`.
    pub fn nibbles_are_identical_up_to_smallest_count(&self, other: &Nibbles) -> bool {
        let smaller_count = self.count.min(other.count);
        (0..smaller_count).all(|i| self.get_nibble(i) == other.get_nibble(i))
    }

    /// Splits the `Nibbles` at the given index, returning two `Nibbles`.
    /// Specifically, if `0x1234` is split at `1`, we get `0x1` and `0x234`.
    ///
    /// # Panics
    /// Panics if the `idx` is out of range.
    pub fn split_at_idx(&self, idx: usize) -> (Nibbles, Nibbles) {
        let post_count = self.count - idx;
        let post_mask = create_mask_of_1s(post_count * 4);

        let post = Nibbles {
            count: post_count,
            packed: self.packed & post_mask,
        };

        let pre_mask = !post_mask;
        let pre_shift_amt = post_count * 4;
        let pre = Nibbles {
            count: idx,
            packed: (self.packed & pre_mask) >> pre_shift_amt,
        };

        (pre, post)
    }

    /// Split the `Nibbles` at the given index but only return the prefix.
    ///
    /// # Panics
    /// Panics if the `idx` is out of range.
    pub fn split_at_idx_prefix(&self, idx: usize) -> Nibbles {
        let shift_amt = (self.count - idx) * 4;
        let pre_mask = create_mask_of_1s(idx * 4) << shift_amt;

        Nibbles {
            count: idx,
            packed: (self.packed & pre_mask) >> shift_amt,
        }
    }

    /// Split the `Nibbles` at the given index but only return the postfix.
    ///
    /// # Panics
    /// Panics if the `idx` is out of range.
    pub fn split_at_idx_postfix(&self, idx: usize) -> Nibbles {
        let postfix_count = self.count - idx;
        let mask = create_mask_of_1s(postfix_count * 4);

        Nibbles {
            count: postfix_count,
            packed: self.packed & mask,
        }
    }

    /// Merge a single Nibble with a `Nibbles`. `self` will be the prefix.
    ///
    /// # Panics
    /// Panics if merging the `Nibble` causes an overflow (total nibbles > 64).
    pub fn merge_nibble(&self, post: Nibble) -> Nibbles {
        self.nibble_append_safety_asserts(post);

        Nibbles {
            count: self.count + 1,
            packed: (self.packed << 4) | post.into(),
        }
    }

    /// Merge two `Nibbles` together. `self` will be the prefix.
    ///
    /// # Panics
    /// Panics if merging the `Nibbles` causes an overflow (total nibbles > 64).
    pub fn merge_nibbles(&self, post: &Nibbles) -> Nibbles {
        let new_count = self.count + post.count;
        assert!(new_count <= 64);

        Nibbles {
            count: new_count,
            packed: (self.packed << (post.count * 4)) | post.packed,
        }
    }

    /// Reverses the `Nibbles` such that the last `Nibble` is now the first
    /// `Nibble`.
    pub fn reverse(&self) -> Nibbles {
        let mut mask = NibblesIntern::from(0xf);
        let mut reversed_packed = NibblesIntern::zero();

        for i in 0..self.count {
            reversed_packed <<= 4;

            let nib = (self.packed & mask) >> (i * 4);
            reversed_packed |= nib;

            mask <<= 4;
        }

        Nibbles {
            count: self.count,
            packed: reversed_packed,
        }
    }

    // TODO: Potentially make faster...
    /// Finds the nibble idx that differs between two nibbles. If there is no
    /// difference, returns 1 + the last index.
    pub fn find_nibble_idx_that_differs_between_nibbles_different_lengths(
        n1: &Nibbles,
        n2: &Nibbles,
    ) -> usize {
        let min_count = n1.count.min(n2.count);

        Self::find_nibble_idx_that_differs_between_nibbles_equal_lengths(
            &n1.get_nibble_range(0..min_count),
            &n2.get_nibble_range(0..min_count),
        )
    }

    /// Finds the nibble index that differs between two `Nibbles` of equal
    /// length. If there is no difference, returns 1 + the last index.
    ///
    /// # Panics
    /// Panics if both `Nibbles` are not the same length.
    pub fn find_nibble_idx_that_differs_between_nibbles_equal_lengths(
        n1: &Nibbles,
        n2: &Nibbles,
    ) -> usize {
        assert_eq!(
            n1.count, n2.count,
            "Tried finding the differing nibble between two nibbles with different sizes! ({n1}, {n2})"
        );

        if n1.count == 0 {
            return n1.count;
        }

        let mut curr_mask: NibblesIntern = (NibblesIntern::from(0xf)) << ((n1.count - 1) * 4);
        for i in 0..n1.count {
            if n1.packed & curr_mask != n2.packed & curr_mask {
                return i;
            }

            curr_mask >>= 4;
        }

        n1.count
    }

    /// Returns a hex representation of the string.
    fn as_hex_str<F>(&self, hex_encode_f: F) -> String
    where
        F: Fn(&[u8]) -> String,
    {
        let mut byte_buf = [0; 40];
        self.packed.to_big_endian(&mut byte_buf);

        let count_bytes = self.min_bytes();
        let hex_string_raw = hex_encode_f(&byte_buf[(40 - count_bytes)..40]);
        let hex_char_iter_raw = hex_string_raw.chars();

        // We need this skip to make both match arms have the same type.
        #[allow(clippy::iter_skip_zero)]
        let mut hex_string = String::from("0x");
        match is_even(self.count) {
            false => hex_string.extend(hex_char_iter_raw.skip(1)),
            true => hex_string.extend(hex_char_iter_raw),
        };

        hex_string
    }

    /// Converts [`Nibbles`] to hex-prefix encoding (AKA "compact").
    /// This appends an extra nibble to the end which encodes if the node is
    /// even and if it's a leaf (terminator) or not.
    pub fn to_hex_prefix_encoding(&self, is_leaf: bool) -> Bytes {
        let num_nibbles = self.count + 1;
        let num_bytes = (num_nibbles + 1) / 2;
        let flag_byte_idx = 41 - num_bytes;

        // Needed because `to_big_endian` always writes `32` bytes.
        let mut bytes = BytesMut::zeroed(41);

        let is_even = is_even(self.count);
        let odd_bit = match is_even {
            false => 1,
            true => 0,
        };

        let term_bit = match is_leaf {
            false => 0,
            true => 1,
        };

        let flags: u8 = (odd_bit | (term_bit << 1)) << 4;
        self.packed.to_big_endian(&mut bytes[1..41]);

        bytes[flag_byte_idx] |= flags;
        Bytes::copy_from_slice(&bytes[flag_byte_idx..41])
    }

    /// Converts a hex prefix byte string ("AKA "compact") into `Nibbles`.
    pub fn from_hex_prefix_encoding(hex_prefix_bytes: &[u8]) -> Result<Self, FromHexPrefixError> {
        if hex_prefix_bytes.len() > 33 {
            return Err(FromHexPrefixError::TooLong(
                hex::encode(hex_prefix_bytes),
                hex_prefix_bytes.len(),
            ));
        }

        let flag_bits = (hex_prefix_bytes[0] & 0b11110000) >> 4;

        // is_odd --> 0b01
        // is_leaf --> 0b10
        let (is_leaf, tot_nib_modifier) = match flag_bits {
            0b00 => (false, -2),
            0b01 => (false, -1),
            0b10 => (true, 0),
            0b11 => (true, 1),
            _ => return Err(FromHexPrefixError::InvalidFlags(flag_bits)),
        };

        // println!("Is leaf: {}, tot_nib_mod: {}", is_leaf, tot_nib_modifier);

        let count = ((hex_prefix_bytes.len() * 2) as isize + tot_nib_modifier) as usize;

        // println!("Count: {}", count);
        let odd_nib_count = count & 0b1 == 1;

        let hex_prefix_byes_iter = hex_prefix_bytes.iter().skip(1).take(32).cloned();

        let mut i = 0;
        let mut nibbles_raw = [0; 40];

        if odd_nib_count {
            Self::write_byte_iter_to_byte_buf(
                &mut nibbles_raw,
                once(hex_prefix_bytes[0] & 0b1111),
                &mut i,
            );
        }

        Self::write_byte_iter_to_byte_buf(&mut nibbles_raw, hex_prefix_byes_iter, &mut i);

        if is_leaf {
            Self::write_byte_iter_to_byte_buf(&mut nibbles_raw, once(16), &mut i);
        }

        let tot_bytes = (count + 1) / 2;

        let x = Self {
            count,
            packed: NibblesIntern::from_big_endian(&nibbles_raw[..tot_bytes]),
        };

        Ok(x)
    }

    fn write_byte_iter_to_byte_buf(buf: &mut [u8], bytes: impl Iterator<Item = u8>, i: &mut usize) {
        for b in bytes {
            buf[*i] = b;
            *i += 1;
        }
    }

    /// Returns the minimum number of bytes needed to represent these `Nibbles`.
    pub const fn min_bytes(&self) -> usize {
        (self.count + 1) / 2
    }

    /// Returns the minimum number of nibbles needed to represent a `U256` key.
    pub fn get_num_nibbles_in_key(k: &NibblesIntern) -> usize {
        (k.bits() + 3) / 4
    }

    /// Returns the nibbles bytes in big-endian format.
    pub fn bytes_be(&self) -> Vec<u8> {
        let mut byte_buf = [0; 40];
        self.packed.to_big_endian(&mut byte_buf);

        byte_buf[40 - self.min_bytes()..40].to_vec()
    }

    /// Creates `Nibbles` from a big endian `H256`.
    pub fn from_h256_be(v: H256) -> Self {
        Self::from_h256_common(|v| NibblesIntern::from_big_endian(v.as_bytes()), v)
    }

    /// Creates `Nibbles` from a little endian `H256`.
    pub fn from_h256_le(v: H256) -> Self {
        Self::from_h256_common(|v| NibblesIntern::from_little_endian(v.as_bytes()), v)
    }

    fn from_h256_common<F: Fn(H256) -> NibblesIntern>(conv_f: F, v: H256) -> Self {
        Self {
            count: 64,
            packed: conv_f(v),
        }
    }

    /// Returns a slice of the internal bytes of packed nibbles.
    /// Only the relevant bytes (up to `count` nibbles) are considered valid.
    pub const fn as_byte_slice(&self) -> &[u8] {
        // Calculate the number of full bytes needed to cover 'count' nibbles
        let bytes_needed = (self.count + 1) / 2; // each nibble is half a byte

        // Safe because we are ensuring the slice size does not exceed the bounds of the
        // array
        unsafe {
            // Convert the pointer to `packed` to a pointer to `u8`
            let packed_ptr = self.packed.0.as_ptr() as *const u8;

            // Create a slice from this pointer and the number of needed bytes
            std::slice::from_raw_parts(packed_ptr, bytes_needed)
        }
    }

    const fn nibble_append_safety_asserts(&self, n: Nibble) {
        assert!(
            self.count < 64,
            "{}",
            MULTIPLE_NIBBLES_APPEND_ASSERT_ERR_MSG
        );
        assert!(n < 16, "{}", SINGLE_NIBBLE_APPEND_ASSERT_ERR_MSG);
    }

    const fn nibbles_append_safety_asserts(&self, new_count: usize) {
        assert!(
            new_count <= 64,
            "{}",
            MULTIPLE_NIBBLES_APPEND_ASSERT_ERR_MSG
        );
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethereum_types::{H256, U256};

    use super::{Nibble, Nibbles, StrToNibblesError, ToNibbles};
    use crate::nibbles::FromHexPrefixError;

    const ZERO_NIBS_63: &str = "0x000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_NIBS_64: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_NIBS_64_LEADING_1: &str =
        "0x1000000000000000000000000000000000000000000000000000000000000000";
    const ZERO_NIBS_64_TRAILING_1: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn get_nibble_works() -> Result<(), StrToNibblesError> {
        let n = Nibbles::from(0x1234);
        assert_eq!(n.get_nibble(0), 0x1);
        assert_eq!(n.get_nibble(3), 0x4);

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(n.get_nibble(30), 0x1);
        assert_eq!(n.get_nibble(33), 0xc);

        Ok(())
    }

    #[test]
    fn pop_nibble_front_works() {
        pop_and_assert_nibbles(0x1, 0x0, 1, Nibbles::pop_next_nibble_front);
        pop_and_assert_nibbles(0x1234, 0x234, 1, Nibbles::pop_next_nibble_front);
        pop_and_assert_nibbles(
            0x1234567890123,
            0x234567890123,
            1,
            Nibbles::pop_next_nibble_front,
        );
    }

    #[test]
    fn pop_nibble_back_works() {
        pop_and_assert_nibbles(0x1, 0x0, 1, Nibbles::pop_next_nibble_back);
        pop_and_assert_nibbles(0x1234, 0x123, 4, Nibbles::pop_next_nibble_back);
        pop_and_assert_nibbles(
            0x1234567890123,
            0x123456789012,
            3,
            Nibbles::pop_next_nibble_back,
        );
    }

    fn pop_and_assert_nibbles<F: Fn(&mut Nibbles) -> Nibble>(
        nibbles: u64,
        expected_nibbles: u64,
        expected_popped_nibble: Nibble,
        pop_f: F,
    ) {
        let mut nibbles = Nibbles::from(nibbles);
        let nib = pop_f(&mut nibbles);
        assert_pop_nibble(&nibbles, expected_nibbles, nib, expected_popped_nibble);
    }

    fn assert_pop_nibble(
        mutated_nibbles: &Nibbles,
        expected_nibbles: u64,
        popped_nibble: Nibble,
        expected_popped_nibble: Nibble,
    ) {
        assert_eq!(*mutated_nibbles, Nibbles::from(expected_nibbles));
        assert_eq!(popped_nibble, expected_popped_nibble)
    }

    #[test]
    fn pop_nibbles_front_works() -> Result<(), StrToNibblesError> {
        let nib = 0x1234.into();

        assert_pop_nibbles(
            &nib,
            0,
            0x1234.into(),
            0x0.into(),
            Nibbles::pop_nibbles_front,
        );
        assert_pop_nibbles(
            &nib,
            1,
            0x234.into(),
            0x1.into(),
            Nibbles::pop_nibbles_front,
        );
        assert_pop_nibbles(
            &nib,
            3,
            0x4.into(),
            0x123.into(),
            Nibbles::pop_nibbles_front,
        );
        assert_pop_nibbles(
            &nib,
            4,
            0x0.into(),
            0x1234.into(),
            Nibbles::pop_nibbles_front,
        );
        assert_pop_nibbles(
            &nib,
            4,
            0x0.into(),
            0x1234.into(),
            Nibbles::pop_nibbles_front,
        );

        let nib = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_pop_nibbles(
            &nib,
            24,
            Nibbles::from_str("0x0ffd1e165c754b28a41a95922f9f70682c581353")?,
            Nibbles::from_str("0x3ab76c381c0f8ea617ea9678")?,
            Nibbles::pop_nibbles_front,
        );

        Ok(())
    }

    #[test]
    fn pop_nibbles_back_works() -> Result<(), StrToNibblesError> {
        let nib = 0x1234.into();

        assert_pop_nibbles(
            &nib,
            0,
            0x1234.into(),
            0x0.into(),
            Nibbles::pop_nibbles_back,
        );
        assert_pop_nibbles(&nib, 1, 0x123.into(), 0x4.into(), Nibbles::pop_nibbles_back);
        assert_pop_nibbles(&nib, 3, 0x1.into(), 0x432.into(), Nibbles::pop_nibbles_back);
        assert_pop_nibbles(
            &nib,
            4,
            0x0.into(),
            0x4321.into(),
            Nibbles::pop_nibbles_back,
        );

        let nib = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_pop_nibbles(
            &nib,
            24,
            Nibbles::from_str("0x3ab76c381c0f8ea617ea96780ffd1e165c754b28")?,
            Nibbles::from_str("0x353185c28607f9f22959a14a")?,
            Nibbles::pop_nibbles_back,
        );

        Ok(())
    }

    fn assert_pop_nibbles<F: Fn(&mut Nibbles, usize) -> Nibbles>(
        orig: &Nibbles,
        n: usize,
        expected_orig_after_pop: Nibbles,
        expected_resulting_nibbles: Nibbles,
        pop_f: F,
    ) {
        let mut nib = *orig;
        let res = pop_f(&mut nib, n);

        assert_eq!(nib, expected_orig_after_pop);
        assert_eq!(res, expected_resulting_nibbles);
    }

    #[test]
    fn push_nibble_front_works() {
        test_and_assert_nib_push_func(Nibbles::default(), 0x1, |n| n.push_nibble_front(0x1));
        test_and_assert_nib_push_func(0x1, 0x21, |n| n.push_nibble_front(0x2));
        test_and_assert_nib_push_func(
            Nibbles::from_str(ZERO_NIBS_63).unwrap(),
            Nibbles::from_str(ZERO_NIBS_64_LEADING_1).unwrap(),
            |n| n.push_nibble_front(0x1),
        );
    }

    #[test]
    fn push_nibble_back_works() {
        test_and_assert_nib_push_func(Nibbles::default(), 0x1, |n| n.push_nibble_back(0x1));
        test_and_assert_nib_push_func(0x1, 0x12, |n| n.push_nibble_back(0x2));
        test_and_assert_nib_push_func(
            Nibbles::from_str(ZERO_NIBS_63).unwrap(),
            Nibbles::from_str(ZERO_NIBS_64_TRAILING_1).unwrap(),
            |n| n.push_nibble_back(0x1),
        );
    }

    #[test]
    fn push_nibbles_front_works() {
        test_and_assert_nib_push_func(Nibbles::default(), 0x1234, |n| {
            n.push_nibbles_front(&0x1234.into())
        });
        test_and_assert_nib_push_func(0x1234, 0x5671234, |n| n.push_nibbles_front(&0x567.into()));
        test_and_assert_nib_push_func(
            Nibbles::from_str(ZERO_NIBS_63).unwrap(),
            Nibbles::from_str(ZERO_NIBS_64_LEADING_1).unwrap(),
            |n| n.push_nibbles_front(&0x1.into()),
        );
    }

    #[test]
    fn push_nibbles_back_works() {
        test_and_assert_nib_push_func(Nibbles::default(), 0x1234, |n| {
            n.push_nibbles_back(&0x1234.into())
        });
        test_and_assert_nib_push_func(0x1234, 0x1234567, |n| n.push_nibbles_back(&0x567.into()));
        test_and_assert_nib_push_func(
            Nibbles::from_str(ZERO_NIBS_63).unwrap(),
            Nibbles::from_str(ZERO_NIBS_64_TRAILING_1).unwrap(),
            |n| n.push_nibbles_back(&0x1.into()),
        );
    }

    fn test_and_assert_nib_push_func<F: Fn(&mut Nibbles), S: Into<Nibbles>, E: Into<Nibbles>>(
        starting_nibs: S,
        expected: E,
        f: F,
    ) {
        let mut nibs = starting_nibs.into();
        (f)(&mut nibs);

        assert_eq!(nibs, expected.into());
    }

    #[test]
    fn get_next_nibbles_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.get_next_nibbles(0), Nibbles::default());
        assert_eq!(n.get_next_nibbles(1), Nibbles::from(0x1));
        assert_eq!(n.get_next_nibbles(2), Nibbles::from(0x12));
        assert_eq!(n.get_next_nibbles(3), Nibbles::from(0x123));
        assert_eq!(n.get_next_nibbles(4), Nibbles::from(0x1234));

        assert_eq!(Nibbles::from(0x0).get_next_nibbles(0), Nibbles::default());

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(
            n.get_next_nibbles(24),
            Nibbles::from_str("0x3ab76c381c0f8ea617ea9678")?
        );

        Ok(())
    }

    #[test]
    fn get_nibble_range_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.get_nibble_range(0..0), 0x0.into());
        assert_eq!(n.get_nibble_range(0..1), 0x1.into());
        assert_eq!(n.get_nibble_range(0..2), 0x12.into());
        assert_eq!(n.get_nibble_range(0..4), 0x1234.into());

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(n.get_nibble_range(16..24), Nibbles::from_str("0x17ea9678")?);

        Ok(())
    }

    #[test]
    fn truncate_nibbles_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.truncate_n_nibbles_front(0), n);
        assert_eq!(n.truncate_n_nibbles_front(1), 0x234.into());
        assert_eq!(n.truncate_n_nibbles_front(2), 0x34.into());
        assert_eq!(n.truncate_n_nibbles_front(3), 0x4.into());
        assert_eq!(n.truncate_n_nibbles_front(4), 0x0.into());
        assert_eq!(n.truncate_n_nibbles_front(8), 0x0.into());

        assert_eq!(n.truncate_n_nibbles_back(0), n);
        assert_eq!(n.truncate_n_nibbles_back(1), 0x123.into());
        assert_eq!(n.truncate_n_nibbles_back(2), 0x12.into());
        assert_eq!(n.truncate_n_nibbles_back(3), 0x1.into());
        assert_eq!(n.truncate_n_nibbles_back(4), 0x0.into());
        assert_eq!(n.truncate_n_nibbles_back(8), 0x0.into());

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(
            n.truncate_n_nibbles_front(16),
            Nibbles::from_str("0x17ea96780ffd1e165c754b28a41a95922f9f70682c581353")?
        );
        assert_eq!(
            n.truncate_n_nibbles_back(16),
            Nibbles::from_str("0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a9592")?
        );

        Ok(())
    }

    #[test]
    fn split_at_idx_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.split_at_idx(0), (0x0.into(), 0x1234.into()));
        assert_eq!(n.split_at_idx(1), (0x1.into(), 0x234.into()));
        assert_eq!(n.split_at_idx(2), (0x12.into(), 0x34.into()));
        assert_eq!(n.split_at_idx(3), (0x123.into(), 0x4.into()));

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(
            n.split_at_idx(24),
            (
                Nibbles::from_str("0x3ab76c381c0f8ea617ea9678")?,
                Nibbles::from_str("0x0ffd1e165c754b28a41a95922f9f70682c581353")?
            )
        );

        Ok(())
    }

    #[test]
    #[should_panic]
    fn split_at_idx_panics_if_out_of_range() {
        Nibbles::from(0x1234).split_at_idx(5);
    }

    #[test]
    fn split_at_idx_prefix_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.split_at_idx_prefix(0), 0x0.into());
        assert_eq!(n.split_at_idx_prefix(1), 0x1.into());
        assert_eq!(n.split_at_idx_prefix(3), 0x123.into());

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(
            n.split_at_idx_prefix(24),
            Nibbles::from_str("0x3ab76c381c0f8ea617ea9678")?
        );

        Ok(())
    }

    #[test]
    fn split_at_idx_postfix_works() -> Result<(), StrToNibblesError> {
        let n: Nibbles = 0x1234.into();

        assert_eq!(n.split_at_idx_postfix(0), 0x1234.into());
        assert_eq!(n.split_at_idx_postfix(1), 0x234.into());
        assert_eq!(n.split_at_idx_postfix(3), 0x4.into());

        let n = Nibbles::from_str(
            "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353",
        )?;
        assert_eq!(
            n.split_at_idx_postfix(24),
            Nibbles::from_str("0x0ffd1e165c754b28a41a95922f9f70682c581353")?
        );

        Ok(())
    }

    #[test]
    fn merge_nibble_works() -> Result<(), StrToNibblesError> {
        assert_eq!(Nibbles::from(0x0).merge_nibble(1), 0x1.into());
        assert_eq!(Nibbles::from(0x1234).merge_nibble(5), 0x12345.into());
        assert_eq!(
            Nibbles::from_str("0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c58135")?
                .merge_nibble(3),
            Nibbles::from_str(
                "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353"
            )?
        );

        Ok(())
    }

    #[test]
    fn merge_nibbles_works() -> Result<(), StrToNibblesError> {
        assert_eq!(
            Nibbles::from(0x12).merge_nibbles(&(0x34.into())),
            0x1234.into()
        );
        assert_eq!(
            Nibbles::from(0x12).merge_nibbles(&(0x0.into())),
            0x12.into()
        );
        assert_eq!(
            Nibbles::from(0x0).merge_nibbles(&(0x34.into())),
            0x34.into()
        );
        assert_eq!(Nibbles::from(0x0).merge_nibbles(&(0x0).into()), 0x0.into());
        assert_eq!(
            Nibbles::from_str("0x3ab76c381c0f8ea617ea96780ffd1e1")?
                .merge_nibbles(&Nibbles::from_str("0x65c754b28a41a95922f9f70682c581353")?),
            Nibbles::from_str(
                "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353"
            )?
        );

        Ok(())
    }

    #[test]
    fn reverse_works() -> Result<(), StrToNibblesError> {
        assert_eq!(Nibbles::from(0x0).reverse(), Nibbles::from(0x0_u64));
        assert_eq!(Nibbles::from(0x1).reverse(), Nibbles::from(0x1_u64));
        assert_eq!(Nibbles::from(0x12).reverse(), Nibbles::from(0x21_u64));
        assert_eq!(Nibbles::from(0x1234).reverse(), Nibbles::from(0x4321_u64));
        assert_eq!(
            Nibbles::from_str("0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c58135")?
                .reverse(),
            Nibbles::from_str("0x53185c28607f9f22959a14a82b457c561e1dff08769ae716ae8f0c183c67ba3")?
        );

        Ok(())
    }

    #[test]
    fn find_nibble_idx_that_differs_between_nibbles_works() -> Result<(), StrToNibblesError> {
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_equal_lengths(
                &(0x1234.into()),
                &(0x2567.into())
            ),
            0
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_equal_lengths(
                &(0x1234.into()),
                &(0x1256.into())
            ),
            2
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_equal_lengths(
                &(0x1234.into()),
                &(0x1235.into())
            ),
            3
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_equal_lengths(
                &(0x1234.into()),
                &(0x1234.into())
            ),
            4
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_different_lengths(
                &(0x1234.into()),
                &(0x12345.into())
            ),
            4
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles_different_lengths(
                &(Nibbles::from_str(
                    "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c58135"
                )?),
                &(Nibbles::from_str(
                    "0x3ab76c381c0f8ea617ea96780ffd1e165c754b28a41ae716ae8f0c183c67ba3"
                )?),
            ),
            44
        );

        Ok(())
    }

    #[test]
    fn nibbles_are_identical_up_to_smallest_count_works() {
        let n: Nibbles = 0x1234.into();

        assert!(n.nibbles_are_identical_up_to_smallest_count(&(0x1234.into())));
        assert!(n.nibbles_are_identical_up_to_smallest_count(&(0x1.into())));
        assert!(n.nibbles_are_identical_up_to_smallest_count(&(0x12.into())));
        assert!(n.nibbles_are_identical_up_to_smallest_count(&(0x12345678.into())));

        assert!(!n.nibbles_are_identical_up_to_smallest_count(&(0x23.into())));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&(0x4.into())));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&(0x5.into())));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&(0x13.into())));
    }

    #[test]
    fn nibbles_to_hex_prefix_encoding_works() {
        assert_eq!(to_hex_prefix_encoding(0x1234, false), 0x1234);
        assert_eq!(to_hex_prefix_encoding(0x1234, true), 0x201234);
        assert_eq!(to_hex_prefix_encoding(0x12345, false), 0x112345);
        assert_eq!(to_hex_prefix_encoding(0x12345, true), 0x312345);
    }

    fn to_hex_prefix_encoding(k: u64, is_leaf: bool) -> u64 {
        let mut bytes_padded = [0; 8];
        let bytes = Nibbles::from(k).to_hex_prefix_encoding(is_leaf);

        println!("Raw bytes: {}", hex::encode(&bytes));

        bytes_padded[8 - bytes.len()..8].clone_from_slice(&bytes);

        println!("Bytes padded: {}", hex::encode(bytes_padded));

        u64::from_be_bytes(bytes_padded)
    }

    #[test]
    fn nibbles_from_hex_prefix_encoding_works() {
        assert_eq!(
            from_hex_prefix_encoding_str_unwrapped("0x001234"),
            Nibbles::from(0x1234)
        );
        assert_eq!(
            from_hex_prefix_encoding_str_unwrapped("0x201234"),
            Nibbles::from(0x123410)
        );
        assert_eq!(
            from_hex_prefix_encoding_str_unwrapped("0x112345"),
            Nibbles::from(0x12345)
        );
        assert_eq!(
            from_hex_prefix_encoding_str_unwrapped("0x312345"),
            Nibbles::from(0x1234510)
        );
        assert_eq!(
            from_hex_prefix_encoding_str_unwrapped(
                "0x2000080000000000000000000000000000000000000000000000000000000000"
            ),
            Nibbles::from_str("0x0008000000000000000000000000000000000000000000000000000000000010")
                .unwrap()
        );
    }

    fn from_hex_prefix_encoding_str(k: &str) -> Result<Nibbles, FromHexPrefixError> {
        Nibbles::from_hex_prefix_encoding(&Nibbles::from_str(k).unwrap().bytes_be())
    }

    fn from_hex_prefix_encoding_str_unwrapped(k: &str) -> Nibbles {
        from_hex_prefix_encoding_str(k).unwrap()
    }

    #[test]
    fn nibbles_from_hex_prefix_encoding_errors_if_flags_invalid() {
        assert!(matches!(
            from_hex_prefix_encoding_str("0x401234"),
            Err(FromHexPrefixError::InvalidFlags(_))
        ));
        assert!(matches!(
            from_hex_prefix_encoding_str("0xF12345"),
            Err(FromHexPrefixError::InvalidFlags(_))
        ));
    }

    #[test]
    fn nibbles_from_hex_prefix_encoding_errors_if_too_large() {
        // 68 bytes long.
        let b = hex::decode("10000000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();

        assert!(matches!(
            Nibbles::from_hex_prefix_encoding(&b),
            Err(FromHexPrefixError::TooLong(_, _))
        ));
    }

    #[test]
    fn nibbles_to_bytes_works() {
        assert_eq!(u64_to_nibbles_and_bytes_back_to_u64(0x0), 0x0);
        assert_eq!(u64_to_nibbles_and_bytes_back_to_u64(0x4), 0x4);
        assert_eq!(u64_to_nibbles_and_bytes_back_to_u64(0x1234), 0x1234);
        assert_eq!(u64_to_nibbles_and_bytes_back_to_u64(0x12345), 0x12345);
        assert_eq!(
            u64_to_nibbles_and_bytes_back_to_u64(0x123456789001aaa),
            0x123456789001aaa
        );
        assert_eq!(
            u64_to_nibbles_and_bytes_back_to_u64(0x123456789001aaaa),
            0x123456789001aaaa
        );
    }

    fn u64_to_nibbles_and_bytes_back_to_u64(v: u64) -> u64 {
        let mut byte_buf = [0; 8];
        let nib = Nibbles::from(v);
        let nib_bytes = nib.bytes_be();

        for (i, b) in nib_bytes.iter().rev().enumerate() {
            byte_buf[7 - i] = *b;
        }

        u64::from_be_bytes(byte_buf)
    }

    #[test]
    fn from_u256_works() {
        assert_eq!(Nibbles::from(0x0), Nibbles::from(0x0));
        assert_eq!(Nibbles::from(0x1), Nibbles::from(0x1));
        assert_eq!(Nibbles::from(0x12), Nibbles::from(0x12));
        assert_eq!(Nibbles::from(0x123), Nibbles::from(0x123));
    }

    #[test]
    fn nibbles_from_h256_works() {
        assert_eq!(
            format!("{:x}", Nibbles::from_h256_be(H256::from_low_u64_be(0))),
            ZERO_NIBS_64,
        );
        assert_eq!(
            format!("{:x}", Nibbles::from_h256_be(H256::from_low_u64_be(2048))),
            "0x0000000000000000000000000000000000000000000000000000000000000800"
        );
        assert_eq!(
            format!("{:x}", Nibbles::from_h256_le(H256::from_low_u64_be(0))),
            ZERO_NIBS_64
        );

        // Note that the first bit of the `Nibbles` changes if the count is odd.
        assert_eq!(
            format!("{:x}", Nibbles::from_h256_le(H256::from_low_u64_be(2048))),
            "0x0008000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn nibbles_into_h256_works() {
        let nibbles: Nibbles = Nibbles::from(0x0);
        let h256_value: H256 = nibbles.into();
        assert_eq!(format!("0x{:x}", h256_value), ZERO_NIBS_64);

        let nibbles: Nibbles = Nibbles::from(2048);
        let h256_value: H256 = nibbles.into();
        assert_eq!(
            format!("0x{:x}", h256_value),
            "0x0000000000000000000000000000000000000000000000000000000000000800",
        );
    }

    #[test]
    fn nibbles_from_str_works() {
        assert_eq!(format!("{:x}", Nibbles::from_str("0x0").unwrap()), "0x0");
        assert_eq!(format!("{:x}", Nibbles::from_str("0").unwrap()), "0x0");
        assert_eq!(
            format!("{:x}", Nibbles::from_str("0x800").unwrap()),
            "0x800"
        );
        assert_eq!(format!("{:x}", Nibbles::from_str("800").unwrap()), "0x800");
    }

    #[test]
    fn nibbles_from_nibble_works() {
        assert_eq!(u64::from(Nibbles::from_nibble(0x0)), 0x0);
        assert_eq!(u64::from(Nibbles::from_nibble(0x1)), 0x1);
        assert_eq!(u64::from(Nibbles::from_nibble(0xf)), 0xf);
    }

    #[test]
    #[should_panic]
    fn nibbles_from_nibble_panics_when_not_nibble() {
        let _ = u64::from(Nibbles::from_nibble(0x10));
    }

    #[test]
    fn to_nibbles_works() {
        assert_eq!(format!("{:x}", 0x0_u64.to_nibbles()), "0x");
        assert_eq!(format!("{:x}", 0x0_u64.to_nibbles_byte_padded()), "0x");

        assert_eq!(format!("{:x}", 0x1_u64.to_nibbles()), "0x1");
        assert_eq!(format!("{:x}", 0x1_u64.to_nibbles_byte_padded()), "0x01");

        assert_eq!(format!("{:x}", 0x1234_u64.to_nibbles()), "0x1234");
        assert_eq!(
            format!("{:x}", 0x1234_u64.to_nibbles_byte_padded()),
            "0x1234"
        );

        assert_eq!(format!("{:x}", 0x1234_usize.to_nibbles()), "0x1234");
        assert_eq!(
            format!("{:x}", 0x1234_usize.to_nibbles_byte_padded()),
            "0x1234"
        );
    }

    #[test]
    fn from_hex_prefix_encoding_edge_case() {
        let v = U256::from_str("3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581353")
            .unwrap();
        let mut buf = [0; 32];
        v.to_big_endian(&mut buf);

        Nibbles::from_hex_prefix_encoding(&buf).unwrap();
    }

    #[test]
    fn nibbles_as_byte_slice_works() -> Result<(), StrToNibblesError> {
        let cases = [
            (0x0, vec![]),
            (0x1, vec![0x01]),
            (0x12, vec![0x12]),
            (0x123, vec![0x23, 0x01]),
        ];

        for case in cases.iter() {
            let nibbles = Nibbles::from(case.0 as u64);
            let byte_vec = nibbles.as_byte_slice().to_vec();
            assert_eq!(byte_vec, case.1.clone(), "Failed for input 0x{:X}", case.0);
        }

        let input = "3ab76c381c0f8ea617ea96780ffd1e165c754b28a41a95922f9f70682c581351";
        let nibbles = Nibbles::from_str(input)?;

        let byte_vec = nibbles.as_byte_slice().to_vec();
        let mut expected_vec: Vec<u8> = hex::decode(input).expect("Invalid hex string");
        expected_vec.reverse();
        assert_eq!(
            byte_vec,
            expected_vec.clone(),
            "Failed for input 0x{}",
            input
        );

        Ok(())
    }
}
