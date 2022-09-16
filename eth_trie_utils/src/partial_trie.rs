use std::{fmt::Debug, fmt::Display, ops::Range};

use ethereum_types::U256;

use crate::{
    types::{EthAddress, Nibble},
    utils::{create_mask_of_1s, is_even},
};

#[derive(Clone, Debug)]
/// A partial trie, or a sub-trie thereof. This mimics the structure of an
/// Ethereum trie, except with an additional `Hash` node type, representing a
/// node whose data is not needed to process our transaction.
pub enum PartialTrie {
    /// An empty trie.
    Empty,
    /// The digest of trie whose data does not need to be stored.
    Hash(U256),
    /// A branch node, which consists of 16 children and an optional value.
    Branch {
        children: [Box<PartialTrie>; 16],
        value: Option<U256>,
    },
    /// An extension node, which consists of a list of nibbles and a single
    /// child.
    Extension {
        nibbles: Nibbles,
        child: Box<PartialTrie>,
    },
    /// A leaf node, which consists of a list of nibbles and a value.
    Leaf { nibbles: Nibbles, value: Vec<u8> },
}

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// A sequence of nibbles.
pub struct Nibbles {
    /// The number of nibbles in this sequence.
    pub count: usize,
    /// A packed encoding of these nibbles. Only the first (least significant)
    /// `4 * count` bits are used. The rest are unused and should be zero.
    pub packed: U256,
}

impl Display for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex_str())
    }
}

// Manual impl in order to print `packed` nicely.
impl Debug for Nibbles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nibbles")
            .field("count", &self.count)
            .field("packed", &self.as_hex_str())
            .finish()
    }
}

impl From<Nibbles> for EthAddress {
    fn from(n: Nibbles) -> Self {
        n.packed
    }
}

impl From<EthAddress> for Nibbles {
    fn from(addr: EthAddress) -> Self {
        Self {
            count: 64, /* Always 64, since we are assuming fixed sized keys and `0`s can make up
                        * a key. */
            packed: addr,
        }
    }
}

impl Nibbles {
    pub fn get_nibble(&self, idx: usize) -> Nibble {
        Self::get_nibble_common(&self.packed, idx, self.count)
    }

    pub fn pop_next_nibble(&mut self) -> Nibble {
        let n = self.get_nibble(0);
        self.truncate_n_nibbles_mut(1);

        n
    }

    pub fn get_next_nibbles(&self, n: usize) -> Nibbles {
        self.get_nibble_range(0..n)
    }

    /// Pops the next `n` proceeding nibbles.
    pub fn pop_next_nibbles(&mut self, n: usize) -> Nibbles {
        let r = self.get_nibble_range(0..n);
        self.truncate_n_nibbles_mut(n);

        r
    }

    pub fn get_nibble_of_eth_addr(addr: &EthAddress, idx: usize) -> Nibble {
        let count = Self::get_num_nibbles_in_addr(addr);
        Self::get_nibble_common(addr, idx, count)
    }

    fn get_nibble_common(addr: &EthAddress, idx: usize, count: usize) -> Nibble {
        let nib_idx = count - idx - 1;
        let byte = addr.byte(nib_idx / 2);

        match is_even(nib_idx) {
            false => (byte & 0b11110000) >> 4,
            true => byte & 0b00001111,
        }
    }

    pub fn get_nibble_range(&self, range: Range<usize>) -> Nibbles {
        Self::get_nibble_range_common(&self.packed, range, self.count)
    }

    fn get_nibble_range_common(addr: &EthAddress, range: Range<usize>, count: usize) -> Nibbles {
        let range_count = range.end - range.start;

        let shift_amt = (count - range.end) * 4;
        let mask = create_mask_of_1s(range_count * 4) << shift_amt;
        let range_packed = (*addr & mask) >> shift_amt;

        Self {
            count: range_count,
            packed: range_packed,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn nibbles_are_identical_up_to_smallest_count(&self, other: &Nibbles) -> bool {
        let smaller_count = self.count.min(other.count);
        (0..smaller_count).all(|i| self.get_nibble(i) == other.get_nibble(i))
    }

    /// Drops the next `n` proceeding nibbles.
    pub fn truncate_n_nibbles(&self, n: usize) -> Nibbles {
        let mut nib = *self;
        nib.truncate_n_nibbles_mut(n);

        nib
    }

    pub fn truncate_n_nibbles_mut(&mut self, n: usize) {
        let mask_shift = (self.count - n) * 4;
        let truncate_mask = !(create_mask_of_1s(n * 4) << mask_shift);

        self.count -= n;
        self.packed = self.packed & truncate_mask;
    }

    /// Splits the `Nibbles` at the given index, returning two `Nibbles`.
    /// Specifically, if `0x1234` is split at `1`, we get `0x1` and `0x234`.
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

    pub fn split_at_idx_prefix(&self, idx: usize) -> Nibbles {
        let shift_amt = (self.count - idx) * 4;
        let pre_mask = create_mask_of_1s(idx * 4) << shift_amt;

        Nibbles {
            count: idx,
            packed: (self.packed & pre_mask) >> shift_amt,
        }
    }

    pub fn split_at_idx_postfix(&self, idx: usize) -> Nibbles {
        let postfix_count = self.count - idx;
        let mask = create_mask_of_1s(postfix_count * 4);

        Nibbles {
            count: postfix_count,
            packed: self.packed & mask,
        }
    }

    /// Merge two `Nibbles` together. `self` will be the prefix.
    pub fn merge(&self, post: &Nibbles) -> Nibbles {
        Nibbles {
            count: self.count + post.count,
            packed: (self.packed << (post.count * 4)) | post.packed,
        }
    }

    /// Finds the nibble idx that differs between two nibbles.
    pub fn find_nibble_idx_that_differs_between_nibbles(n1: &Nibbles, n2: &Nibbles) -> usize {
        // Good assumption?
        assert_eq!(
            n1.count, n2.count,
            "Tried finding the differing nibble between two nibbles with different sizes! ({}, {})",
            n1, n2
        );

        let mut curr_mask: U256 = (U256::from(0xf)) << ((n1.count - 1) * 4);
        for i in 0..n1.count {
            if n1.packed & curr_mask != n2.packed & curr_mask {
                return i;
            }

            curr_mask >>= 4;
        }

        panic!(
            "Unable to find a nibble that differs between the two given nibbles! (n1: {:?}, n2: {:?})",
            n1, n2
        );
    }

    pub fn get_num_nibbles_in_addr(addr: &EthAddress) -> usize {
        (addr.bits() + 3) / 4
    }

    // TODO: Make nicer...
    fn as_hex_str(&self) -> String {
        let mut byte_buf = [0; 32];
        self.packed.to_big_endian(&mut byte_buf);

        let count_bytes = (self.count + 1) / 2;
        let hex_string_raw = hex::encode(&byte_buf[(32 - count_bytes)..32]);
        let hex_char_iter_raw = hex_string_raw.chars();

        let hex_char_iter = match is_even(self.count) {
            false => hex_char_iter_raw.skip(1),
            true => hex_char_iter_raw.skip(0),
        };

        let mut hex_string = String::from("0x");
        hex_string.extend(hex_char_iter);

        hex_string
    }
}

#[cfg(test)]
mod tests {

    use super::Nibbles;
    use crate::{testing_utils::eth_addr, types::EthAddress, utils::nibbles};

    #[test]
    fn get_nibble_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.get_nibble(0), 0x1);
        assert_eq!(n.get_nibble(3), 0x4);
    }

    #[test]
    fn pop_next_nibbles_works() {
        let nib = nibbles(0x1234);

        assert_pop_nibbles(&nib, 0, nibbles(0x1234), nibbles(0x0));
        assert_pop_nibbles(&nib, 1, nibbles(0x234), nibbles(0x1));
        assert_pop_nibbles(&nib, 3, nibbles(0x4), nibbles(0x123));
        assert_pop_nibbles(&nib, 4, nibbles(0x0), nibbles(0x1234));
    }

    fn assert_pop_nibbles(
        orig: &Nibbles,
        n: usize,
        expected_orig_after_pop: Nibbles,
        expected_resulting_nibbles: Nibbles,
    ) {
        let mut nib = *orig;
        let res = nib.pop_next_nibbles(n);

        assert_eq!(nib, expected_orig_after_pop);
        assert_eq!(res, expected_resulting_nibbles);
    }

    #[test]
    fn get_nibble_range_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.get_nibble_range(0..0), nibbles(0x0));
        assert_eq!(n.get_nibble_range(0..1), nibbles(0x1));
        assert_eq!(n.get_nibble_range(0..2), nibbles(0x12));
        assert_eq!(n.get_nibble_range(0..4), nibbles(0x1234));
    }

    #[test]
    fn truncate_nibble_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.truncate_n_nibbles(0), n);
        assert_eq!(n.truncate_n_nibbles(1), nibbles(0x234));
        assert_eq!(n.truncate_n_nibbles(2), nibbles(0x34));
        assert_eq!(n.truncate_n_nibbles(4), nibbles(0x0));
    }

    #[test]
    fn split_at_idx_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.split_at_idx(0), (nibbles(0x0), nibbles(0x1234)));
        assert_eq!(n.split_at_idx(1), (nibbles(0x1), nibbles(0x234)));
        assert_eq!(n.split_at_idx(2), (nibbles(0x12), nibbles(0x34)));
        assert_eq!(n.split_at_idx(3), (nibbles(0x123), nibbles(0x4)));
    }

    #[test]
    fn split_at_idx_prefix_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.split_at_idx_prefix(0), nibbles(0x0));
        assert_eq!(n.split_at_idx_prefix(1), nibbles(0x1));
        assert_eq!(n.split_at_idx_prefix(3), nibbles(0x123));
    }

    #[test]
    fn split_at_idx_postfix_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.split_at_idx_postfix(0), nibbles(0x1234));
        assert_eq!(n.split_at_idx_postfix(1), nibbles(0x234));
        assert_eq!(n.split_at_idx_postfix(3), nibbles(0x4));
    }

    #[test]
    fn get_nibble_of_eth_addr_works() {
        let a = eth_addr(0x1234);

        assert_eq!(Nibbles::get_nibble_of_eth_addr(&a, 0), 0x1);
        assert_eq!(Nibbles::get_nibble_of_eth_addr(&a, 1), 0x2);
        assert_eq!(Nibbles::get_nibble_of_eth_addr(&a, 3), 0x4);
    }

    #[test]
    fn merge_works() {
        assert_eq!(nibbles(0x12).merge(&nibbles(0x34)), nibbles(0x1234));
        assert_eq!(nibbles(0x12).merge(&nibbles(0x0)), nibbles(0x12));
        assert_eq!(nibbles(0x0).merge(&nibbles(0x34)), nibbles(0x34));
        assert_eq!(nibbles(0x0).merge(&nibbles(0x0)), nibbles(0x0));
    }

    #[test]
    fn find_nibble_idx_that_differs_between_nibbles_works() {
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles(
                &nibbles(0x1234),
                &nibbles(0x2567)
            ),
            0
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles(
                &nibbles(0x1234),
                &nibbles(0x1256)
            ),
            2
        );
        assert_eq!(
            Nibbles::find_nibble_idx_that_differs_between_nibbles(
                &nibbles(0x1234),
                &nibbles(0x1235)
            ),
            3
        );
    }

    #[test]
    fn nibbles_are_identical_up_to_smallest_count_works() {
        let n = nibbles(0x1234);

        assert!(n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x1234)));
        assert!(n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x1)));
        assert!(n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x12)));

        assert!(!n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x23)));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x4)));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x5)));
        assert!(!n.nibbles_are_identical_up_to_smallest_count(&nibbles(0x13)));
    }

    #[test]
    fn eth_addr_to_nibbles_works() {
        let addr = EthAddress::from(0x12);
        let nib = Nibbles::from(addr);

        assert_eq!(nib.count, 64);
        assert_eq!(nib.packed, EthAddress::from(0x12));
    }
}
