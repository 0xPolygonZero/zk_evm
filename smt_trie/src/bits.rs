use std::ops::Add;

use ethereum_types::{BigEndianHash, H256, U256};
use serde::{Deserialize, Serialize};

pub type Bit = bool;

#[derive(
    Copy, Clone, Deserialize, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Debug,
)]
pub struct Bits {
    /// The number of bits in this sequence.
    pub count: usize,
    /// A packed encoding of these bits. Only the first (least significant)
    /// `count` bits are used. The rest are unused and should be zero.
    pub packed: U256,
}

impl From<U256> for Bits {
    fn from(packed: U256) -> Self {
        Bits { count: 256, packed }
    }
}

impl From<H256> for Bits {
    fn from(packed: H256) -> Self {
        Bits {
            count: 256,
            packed: packed.into_uint(),
        }
    }
}

impl Add for Bits {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert!(self.count + rhs.count <= 256, "Overflow");
        Self {
            count: self.count + rhs.count,
            packed: self.packed * (U256::one() << rhs.count) + rhs.packed,
        }
    }
}

impl Bits {
    pub const fn empty() -> Self {
        Bits {
            count: 0,
            packed: U256::zero(),
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn pop_next_bit(&mut self) -> Bit {
        assert!(!self.is_empty(), "Cannot pop from empty bits");
        let b = !(self.packed & U256::one()).is_zero();
        self.packed >>= 1;
        self.count -= 1;
        b
    }

    pub fn get_bit(&self, i: usize) -> Bit {
        assert!(i < self.count, "Index out of bounds");
        !(self.packed & (U256::one() << (self.count - 1 - i))).is_zero()
    }

    pub fn push_bit(&mut self, bit: Bit) {
        self.packed = self.packed * 2 + U256::from(bit as u64);
        self.count += 1;
    }

    pub fn add_bit(&self, bit: Bit) -> Self {
        let mut x = *self;
        x.push_bit(bit);
        x
    }

    pub fn common_prefix(&self, k: &Bits) -> (Self, Option<(Bit, Bit)>) {
        let mut a = *self;
        let mut b = *k;
        while a.count > b.count {
            a.pop_next_bit();
        }
        while a.count < b.count {
            b.pop_next_bit();
        }
        if a == b {
            return (a, None);
        }
        let mut a_bit = a.pop_next_bit();
        let mut b_bit = b.pop_next_bit();
        while a != b {
            a_bit = a.pop_next_bit();
            b_bit = b.pop_next_bit();
        }
        assert_ne!(a_bit, b_bit, "Sanity check.");
        (a, Some((a_bit, b_bit)))
    }
}
