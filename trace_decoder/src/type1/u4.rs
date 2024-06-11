use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(u8)]
pub enum U4 {
    #[default]
    Dec00 = 0b0000_0000,
    Dec01 = 0b0000_0001,
    Dec02 = 0b0000_0010,
    Dec03 = 0b0000_0011,
    Dec04 = 0b0000_0100,
    Dec05 = 0b0000_0101,
    Dec06 = 0b0000_0110,
    Dec07 = 0b0000_0111,
    Dec08 = 0b0000_1000,
    Dec09 = 0b0000_1001,
    Dec10 = 0b0000_1010,
    Dec11 = 0b0000_1011,
    Dec12 = 0b0000_1100,
    Dec13 = 0b0000_1101,
    Dec14 = 0b0000_1110,
    Dec15 = 0b0000_1111,
}

impl fmt::Debug for U4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&(*self as u8), f)
    }
}

impl U4 {
    pub const fn new(byte: u8) -> Option<Self> {
        Some(match byte {
            0b0000_0000 => Self::Dec00,
            0b0000_0001 => Self::Dec01,
            0b0000_0010 => Self::Dec02,
            0b0000_0011 => Self::Dec03,
            0b0000_0100 => Self::Dec04,
            0b0000_0101 => Self::Dec05,
            0b0000_0110 => Self::Dec06,
            0b0000_0111 => Self::Dec07,
            0b0000_1000 => Self::Dec08,
            0b0000_1001 => Self::Dec09,
            0b0000_1010 => Self::Dec10,
            0b0000_1011 => Self::Dec11,
            0b0000_1100 => Self::Dec12,
            0b0000_1101 => Self::Dec13,
            0b0000_1110 => Self::Dec14,
            0b0000_1111 => Self::Dec15,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct U4x2 {
    pub packed: u8,
}

impl U4x2 {
    pub const fn left(&self) -> U4 {
        match U4::new(self.packed >> 4) {
            Some(it) => it,
            None => unreachable!(),
        }
    }
    pub const fn right(&self) -> U4 {
        match U4::new(self.packed & 0b0000_1111) {
            Some(it) => it,
            None => unreachable!(),
        }
    }
}
