use std::{fmt::Display, ops::Range};

use ethereum_types::U256;

use crate::{
    trie_builder::Nibble,
    types::EthAddress,
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

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
        write!(f, "0x{}", self.packed)
    }
}

impl From<Nibbles> for EthAddress {
    fn from(n: Nibbles) -> Self {
        n.packed
    }
}

impl Nibbles {
    pub fn get_nibble(&self, idx: usize) -> Nibble {
        Self::get_nibble_common(&self.packed, idx, self.count)
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

    /// Gets a range of nibbles within the nibbles.
    pub fn get_nibble_range_from_eth_addr(addr: &EthAddress, range: Range<usize>) -> Nibbles {
        let count = Self::get_num_nibbles_in_addr(addr);
        Self::get_nibble_range_common(addr, range, count)
    }

    fn get_nibble_range_common(addr: &EthAddress, range: Range<usize>, count: usize) -> Nibbles {
        let range_count = range.end - range.start;

        // let count = range.end - range.start;
        let shift_amt = (count - range.end) * 4;
        let mask = create_mask_of_1s(range_count * 4) << shift_amt;
        let range_packed = (*addr & mask) >> shift_amt;

        Self {
            count: range_count,
            packed: range_packed,
        }
    }

    /// Drops the next `n` proceeding nibbles.
    pub fn truncate_n_nibbles(&self, n: usize) -> Nibbles {
        let mask_shift = (self.count - n) * 4;
        let truncate_mask = !(create_mask_of_1s(n * 4) << mask_shift);

        Self {
            count: self.count - n,
            packed: self.packed & truncate_mask,
        }
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
        let mut curr_mask: U256 = 0xf.into();

        for i in 0..64 {
            if n1.packed & curr_mask != n2.packed & curr_mask {
                return i;
            }

            curr_mask <<= 4;
        }

        panic!(
            "Unable to find a nibble that differs between the two given nibbles! (n1: {:?}, n2: {:?})",
            n1, n2
        );
    }

    pub fn get_num_nibbles_in_addr(addr: &EthAddress) -> usize {
        (addr.bits() + 3) / 4
    }
}

#[cfg(test)]
mod tests {
    use super::Nibbles;
    use crate::types::EthAddress;

    fn nibbles(addr: u64) -> Nibbles {
        eth_addr(addr).into()
    }

    fn eth_addr(addr: u64) -> EthAddress {
        EthAddress::from(addr)
    }

    #[test]
    fn get_nibble_works() {
        let n = nibbles(0x1234);

        assert_eq!(n.get_nibble(0), 0x1);
        assert_eq!(n.get_nibble(3), 0x4);
    }

    #[test]
    fn get_nibble_range_of_eth_addr_works() {
        let a = eth_addr(0x1234);

        assert_eq!(
            Nibbles::get_nibble_range_from_eth_addr(&a, 0..0),
            nibbles(0x0)
        );
        assert_eq!(
            Nibbles::get_nibble_range_from_eth_addr(&a, 0..1),
            nibbles(0x1)
        );
        assert_eq!(
            Nibbles::get_nibble_range_from_eth_addr(&a, 0..2),
            nibbles(0x12)
        );
        assert_eq!(
            Nibbles::get_nibble_range_from_eth_addr(&a, 0..4),
            nibbles(0x1234)
        );
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
}
