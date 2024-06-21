use core::ops::{Add, Mul, Neg};

use ethereum_types::{U256, U512};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;

use crate::extension_tower::{Adj, FieldExt, Fp12, Fp2, Fp6, Stack, BLS381};

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct CurveAff<T>
where
    T: FieldExt,
{
    pub x: T,
    pub y: T,
}

impl<T: FieldExt> CurveAff<T> {
    pub(crate) const fn unit() -> Self {
        CurveAff {
            x: T::ZERO,
            y: T::ZERO,
        }
    }
}

impl<T: FieldExt + Stack> Stack for CurveAff<T> {
    const SIZE: usize = 2 * T::SIZE;

    fn to_stack(&self) -> Vec<U256> {
        let mut stack = self.x.to_stack();
        stack.extend(self.y.to_stack());
        stack
    }

    fn from_stack(stack: &[U256]) -> Self {
        CurveAff {
            x: T::from_stack(&stack[0..T::SIZE]),
            y: T::from_stack(&stack[T::SIZE..2 * T::SIZE]),
        }
    }
}

#[cfg(test)]
impl<T> CurveAff<T>
where
    T: FieldExt,
    CurveAff<T>: CyclicGroup,
{
    pub(crate) fn int(z: i32) -> Self {
        CurveAff::<T>::GENERATOR * z
    }
}

impl<T> Distribution<CurveAff<T>> for Standard
where
    T: FieldExt,
    CurveAff<T>: CyclicGroup,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CurveAff<T> {
        CurveAff::<T>::GENERATOR * rng.gen::<i32>()
    }
}

/// Standard addition formula for elliptic curves, restricted to the cases  
/// <https://en.wikipedia.org/wiki/Elliptic_curve#Algebraic_interpretation>
impl<T: FieldExt> Add for CurveAff<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self == CurveAff::<T>::unit() {
            return other;
        }
        if other == CurveAff::<T>::unit() {
            return self;
        }
        if self == -other {
            return CurveAff::<T>::unit();
        }
        let m = if self == other {
            T::new(3) * self.x * self.x / (T::new(2) * self.y)
        } else {
            (other.y - self.y) / (other.x - self.x)
        };
        let x = m * m - (self.x + other.x);
        CurveAff {
            x,
            y: m * (self.x - x) - self.y,
        }
    }
}

impl<T: FieldExt> Neg for CurveAff<T> {
    type Output = CurveAff<T>;

    fn neg(self) -> Self {
        CurveAff {
            x: self.x,
            y: -self.y,
        }
    }
}

pub trait CyclicGroup {
    const GENERATOR: Self;
}

impl<T> Mul<i32> for CurveAff<T>
where
    T: FieldExt,
    CurveAff<T>: CyclicGroup,
{
    type Output = CurveAff<T>;

    fn mul(self, other: i32) -> Self {
        if other == 0 {
            return CurveAff::<T>::unit();
        }
        if self == CurveAff::<T>::unit() {
            return CurveAff::<T>::unit();
        }
        if other == 1 {
            return self;
        }

        let mut x: CurveAff<T> = self;
        if other.is_negative() {
            x = -x;
        }
        let mut result = CurveAff::<T>::unit();

        let mut exp = other.unsigned_abs() as usize;
        while exp > 0 {
            if exp % 2 == 1 {
                result = result + x;
            }
            exp >>= 1;
            x = x + x;
        }
        result
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct CurveProj<T>
where
    T: FieldExt,
{
    pub x: T,
    pub y: T,
    pub z: T,
}

impl<T: FieldExt + Stack> Stack for CurveProj<T> {
    const SIZE: usize = 3 * T::SIZE;

    fn to_stack(&self) -> Vec<U256> {
        let mut stack = self.x.to_stack();
        stack.extend(self.y.to_stack());
        stack.extend(self.z.to_stack());
        stack
    }

    fn from_stack(stack: &[U256]) -> Self {
        CurveProj {
            x: T::from_stack(&stack[0..T::SIZE]),
            y: T::from_stack(&stack[T::SIZE..2 * T::SIZE]),
            z: T::from_stack(&stack[2 * T::SIZE..3 * T::SIZE]),
        }
    }
}

/// The tangent and chord functions output sparse Fp12 elements.
/// This map embeds the nonzero coefficients into an Fp12.
#[cfg(test)]
pub(crate) const fn sparse_embed<F>(g000: F, g01: Fp2<F>, g11: Fp2<F>) -> Fp12<F>
where
    F: FieldExt,
    Fp2<F>: Adj,
{
    let g0 = Fp6 {
        t0: Fp2 {
            re: g000,
            im: F::ZERO,
        },
        t1: g01,
        t2: Fp2::<F>::ZERO,
    };

    let g1 = Fp6 {
        t0: Fp2::<F>::ZERO,
        t1: g11,
        t2: Fp2::<F>::ZERO,
    };

    Fp12 { z0: g0, z1: g1 }
}

/// Generates a sparse, random Fp12 element.
#[cfg(test)]
pub(crate) fn gen_fp12_sparse<F, R: Rng + ?Sized>(rng: &mut R) -> Fp12<F>
where
    F: FieldExt,
    Fp2<F>: Adj,
    Standard: Distribution<F>,
{
    sparse_embed::<F>(rng.gen::<F>(), rng.gen::<Fp2<F>>(), rng.gen::<Fp2<F>>())
}

#[cfg(test)]
pub mod bn254 {
    use super::*;
    use crate::extension_tower::BN254;

    /// The BN curve consists of pairs
    ///     (x, y): (BN254, BN254) | y^2 = x^3 + 3
    // with generator given by (1, 2).
    impl CyclicGroup for CurveAff<BN254> {
        const GENERATOR: CurveAff<BN254> = CurveAff {
            x: BN254 { val: U256::one() },
            y: BN254 {
                val: U256([2, 0, 0, 0]),
            },
        };
    }

    /// The twisted curve consists of pairs
    ///     (x, y): (Fp2<BN254>, Fp2<BN254>) | y^2 = x^3 + 3/(9 + i)
    /// with generator given as follows:
    impl CyclicGroup for CurveAff<Fp2<BN254>> {
        const GENERATOR: CurveAff<Fp2<BN254>> = CurveAff {
            x: Fp2 {
                re: BN254 {
                    val: U256([
                        0x46debd5cd992f6ed,
                        0x674322d4f75edadd,
                        0x426a00665e5c4479,
                        0x1800deef121f1e76,
                    ]),
                },
                im: BN254 {
                    val: U256([
                        0x97e485b7aef312c2,
                        0xf1aa493335a9e712,
                        0x7260bfb731fb5d25,
                        0x198e9393920d483a,
                    ]),
                },
            },
            y: Fp2 {
                re: BN254 {
                    val: U256([
                        0x4ce6cc0166fa7daa,
                        0xe3d1e7690c43d37b,
                        0x4aab71808dcb408f,
                        0x12c85ea5db8c6deb,
                    ]),
                },
                im: BN254 {
                    val: U256([
                        0x55acdadcd122975b,
                        0xbc4b313370b38ef3,
                        0xec9e99ad690c3395,
                        0x090689d0585ff075,
                    ]),
                },
            },
        };
    }

    /// The sloped line function for doubling a point.
    pub(crate) fn tangent(p: CurveAff<BN254>, q: CurveAff<Fp2<BN254>>) -> Fp12<BN254> {
        let cx = -BN254::new(3) * p.x * p.x;
        let cy = BN254::new(2) * p.y;
        sparse_embed::<BN254>(p.y * p.y - BN254::new(9), q.x * cx, q.y * cy)
    }

    /// The sloped line function for adding two points.
    pub(crate) fn chord(
        p1: CurveAff<BN254>,
        p2: CurveAff<BN254>,
        q: CurveAff<Fp2<BN254>>,
    ) -> Fp12<BN254> {
        let cx = p2.y - p1.y;
        let cy = p1.x - p2.x;
        sparse_embed::<BN254>(p1.y * p2.x - p2.y * p1.x, q.x * cx, q.y * cy)
    }

    // The tate pairing takes points from the curve and its twist and outputs
    // an Fp12 element.
    pub(crate) fn tate(p: CurveAff<BN254>, q: CurveAff<Fp2<BN254>>) -> Fp12<BN254> {
        let miller_output = miller_loop(p, q);
        final_exponent(miller_output)
    }

    /// Standard code for miller loop, can be found on page 99 at this url:
    /// <https://static1.squarespace.com/static/5fdbb09f31d71c1227082339/t/5ff394720493bd28278889c6/1609798774687/PairingsForBeginners.pdf#page=107>
    /// where BN_EXP is a hardcoding of the array of Booleans that the loop
    /// traverses.
    pub(crate) fn miller_loop(p: CurveAff<BN254>, q: CurveAff<Fp2<BN254>>) -> Fp12<BN254> {
        let mut r = p;
        let mut acc: Fp12<BN254> = Fp12::<BN254>::UNIT;
        let mut line: Fp12<BN254>;

        for i in BN_EXP {
            line = tangent(r, q);
            r = r + r;
            acc = line * acc * acc;
            if i {
                line = chord(p, r, q);
                r = r + p;
                acc = line * acc;
            }
        }
        acc
    }

    /// The output y of the miller loop is not an invariant,
    /// but one gets an invariant by raising y to the power
    ///     (p^12 - 1)/N = (p^6 - 1)(p^2 + 1)(p^4 - p^2 + 1)/N
    /// where N is the cyclic group order of the curve.
    /// To achieve this, we first exponentiate y by p^6 - 1 via
    ///     y = y_6 / y
    /// and then exponentiate the result by p^2 + 1 via
    ///     y = y_2 * y
    /// We then note that (p^4 - p^2 + 1)/N can be rewritten as
    ///     (p^4 - p^2 + 1)/N = p^3 + (a2)p^2 + (a1)p - a0
    /// where 0 < a0, a1, a2 < p. Then the final power is given by
    ///     y = y_3 * (y^a2)_2 * (y^a1)_1 * (y^-a0).
    pub(crate) fn final_exponent(f: Fp12<BN254>) -> Fp12<BN254> {
        let mut y = f.frob(6) / f;
        y = y.frob(2) * y;
        let (y_a2, y_a1, y_a0) = get_custom_powers(y);
        y.frob(3) * y_a2.frob(2) * y_a1.frob(1) * y_a0
    }

    /// We first together (so as to avoid repeated steps) compute
    ///     y^a4, y^a2, y^a0
    /// where a1 is given by
    ///     a1 = a4 + 2a2 - a0
    /// we then invert y^a0 and return
    ///     y^a2, y^a1 = y^a4 * y^a2 * y^a2 * y^(-a0), y^(-a0)
    ///
    /// Representing a4, a2, a0 in *little endian* binary, define
    ///     BN_EXPS4 = [(a4[i], a2[i], a0[i]) for i in       0..len(a4)]
    ///     BN_EXPS2 = [       (a2[i], a0[i]) for i in len(a4)..len(a2)]
    ///     BN_EXPS0 = [               a0[i]  for i in len(a2)..len(a0)]
    fn get_custom_powers(f: Fp12<BN254>) -> (Fp12<BN254>, Fp12<BN254>, Fp12<BN254>) {
        let mut sq: Fp12<BN254> = f;
        let mut y0: Fp12<BN254> = Fp12::<BN254>::UNIT;
        let mut y2: Fp12<BN254> = Fp12::<BN254>::UNIT;
        let mut y4: Fp12<BN254> = Fp12::<BN254>::UNIT;

        // proceed via standard squaring algorithm for exponentiation

        // must keep multiplying all three values: a4, a2, a0
        for (a, b, c) in BN_EXPS4 {
            if a {
                y4 = y4 * sq;
            }
            if b {
                y2 = y2 * sq;
            }
            if c {
                y0 = y0 * sq;
            }
            sq = sq * sq;
        }
        // leading term of a4 is always 1
        y4 = y4 * sq;

        // must keep multiplying remaining two values: a2, a0
        for (a, b) in BN_EXPS2 {
            if a {
                y2 = y2 * sq;
            }
            if b {
                y0 = y0 * sq;
            }
            sq = sq * sq;
        }
        // leading term of a2 is always 1
        y2 = y2 * sq;

        // must keep multiplying final remaining value: a0
        for a in BN_EXPS0 {
            if a {
                y0 = y0 * sq;
            }
            sq = sq * sq;
        }
        // leading term of a0 is always 1
        y0 = y0 * sq;

        // invert y0 to compute y^(-a0)
        let y0_inv = y0.inv();

        // return y^a2 = y2, y^a1 = y4 * y2^2 * y^(-a0), y^(-a0)
        (y2, y4 * y2 * y2 * y0_inv, y0_inv)
    }

    const BN_EXP: [bool; 253] = [
        true, false, false, false, false, false, true, true, false, false, true, false, false,
        false, true, false, false, true, true, true, false, false, true, true, true, false, false,
        true, false, true, true, true, false, false, false, false, true, false, false, true, true,
        false, false, false, true, true, false, true, false, false, false, false, false, false,
        false, true, false, true, false, false, true, true, false, true, true, true, false, false,
        false, false, true, false, true, false, false, false, false, false, true, false, false,
        false, true, false, true, true, false, true, true, false, true, true, false, true, false,
        false, false, false, false, false, true, true, false, false, false, false, false, false,
        true, false, true, false, true, true, false, false, false, false, true, false, true, true,
        true, false, true, false, false, true, false, true, false, false, false, false, false,
        true, true, false, false, true, true, true, true, true, false, true, false, false, false,
        false, true, false, false, true, false, false, false, false, true, true, true, true, false,
        false, true, true, false, true, true, true, false, false, true, false, true, true, true,
        false, false, false, false, true, false, false, true, false, false, false, true, false,
        true, false, false, false, false, true, true, true, true, true, false, false, false, false,
        true, true, true, true, true, false, true, false, true, true, false, false, true, false,
        false, true, true, true, true, true, true, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false,
    ];

    // The following constants are defined above get_custom_powers.
    const BN_EXPS4: [(bool, bool, bool); 64] = [
        (true, true, false),
        (true, true, true),
        (true, true, true),
        (false, false, false),
        (false, false, true),
        (true, false, true),
        (false, true, false),
        (true, false, true),
        (true, true, false),
        (true, false, true),
        (false, true, false),
        (true, true, false),
        (true, true, false),
        (true, true, false),
        (false, true, false),
        (false, true, false),
        (false, false, true),
        (true, false, true),
        (true, true, false),
        (false, true, false),
        (true, true, false),
        (true, true, false),
        (true, true, false),
        (false, false, true),
        (false, false, true),
        (true, false, true),
        (true, false, true),
        (true, true, false),
        (true, false, false),
        (true, true, false),
        (false, true, false),
        (true, true, false),
        (true, false, false),
        (false, true, false),
        (false, false, false),
        (true, false, false),
        (true, false, false),
        (true, false, true),
        (false, false, true),
        (false, true, true),
        (false, false, true),
        (false, true, true),
        (false, true, true),
        (false, false, false),
        (true, true, true),
        (true, false, true),
        (true, false, true),
        (false, true, true),
        (true, false, true),
        (false, true, true),
        (false, true, true),
        (true, true, false),
        (true, true, false),
        (true, true, false),
        (true, false, false),
        (false, false, true),
        (true, false, false),
        (false, false, true),
        (true, false, true),
        (true, true, false),
        (true, true, true),
        (false, true, true),
        (false, true, false),
        (true, true, true),
    ];

    const BN_EXPS2: [(bool, bool); 62] = [
        (true, false),
        (true, true),
        (false, false),
        (true, false),
        (true, false),
        (true, true),
        (true, false),
        (true, true),
        (true, false),
        (false, true),
        (false, true),
        (true, true),
        (true, true),
        (false, false),
        (true, true),
        (false, false),
        (false, false),
        (false, true),
        (false, true),
        (true, true),
        (true, true),
        (true, true),
        (false, true),
        (true, true),
        (false, false),
        (true, true),
        (true, false),
        (true, true),
        (false, false),
        (true, true),
        (true, true),
        (true, false),
        (false, false),
        (false, true),
        (false, false),
        (true, true),
        (false, true),
        (false, false),
        (true, false),
        (false, true),
        (false, true),
        (true, false),
        (false, true),
        (false, false),
        (false, false),
        (false, false),
        (false, true),
        (true, false),
        (true, true),
        (false, true),
        (true, true),
        (true, false),
        (false, true),
        (false, false),
        (true, false),
        (false, true),
        (true, false),
        (true, true),
        (true, false),
        (true, true),
        (false, true),
        (true, true),
    ];

    const BN_EXPS0: [bool; 65] = [
        false, false, true, false, false, true, true, false, true, false, true, true, true, false,
        true, false, false, false, true, false, false, true, false, true, false, true, true, false,
        false, false, false, false, true, false, true, false, true, true, true, false, false, true,
        true, true, true, false, true, false, true, true, false, false, true, false, false, false,
        true, true, true, true, false, false, true, true, false,
    ];
}

// The optimal Ate pairing implementation for BLS12-381 has been taken from
// <https://github.com/zkcrypto/bls12_381>.
pub mod bls381 {
    use anyhow::{anyhow, Result};

    use super::*;
    use crate::extension_tower::BLS_BASE;

    const B_G1: BLS381 = BLS381 {
        val: U512([4, 0, 0, 0, 0, 0, 0, 0]),
    };

    /// The BLS curve consists of pairs
    ///     (x, y): (BLS381, BLS381) | y^2 = x^3 + 4
    // with generator given by
    //      x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
    //      y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
    impl CyclicGroup for CurveAff<BLS381> {
        const GENERATOR: CurveAff<BLS381> = CurveAff {
            x: BLS381 {
                val: U512([
                    0xfb3af00adb22c6bb,
                    0x6c55e83ff97a1aef,
                    0xa14e3a3f171bac58,
                    0xc3688c4f9774b905,
                    0x2695638c4fa9ac0f,
                    0x17f1d3a73197d794,
                    0,
                    0,
                ]),
            },
            y: BLS381 {
                val: U512([
                    0x0caa232946c5e7e1,
                    0xd03cc744a2888ae4,
                    0x00db18cb2c04b3ed,
                    0xfcf5e095d5d00af6,
                    0xa09e30ed741d8ae4,
                    0x08b3f481e3aaa0f1,
                    0,
                    0,
                ]),
            },
        };
    }

    /// The twisted curve consists of pairs
    ///     (x, y): (Fp2<BLS381>, Fp2<BLS381>) | y^2 = x^3 + 4*(i + 1)
    /// with generator given by
    //      x = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
    //          + 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 * i
    //      y = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
    //          + 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582 * i
    impl CyclicGroup for CurveAff<Fp2<BLS381>> {
        const GENERATOR: CurveAff<Fp2<BLS381>> = CurveAff {
            x: Fp2 {
                re: BLS381 {
                    val: U512([
                        0xd48056c8c121bdb8,
                        0x0bac0326a805bbef,
                        0xb4510b647ae3d177,
                        0xc6e47ad4fa403b02,
                        0x260805272dc51051,
                        0x024aa2b2f08f0a91,
                        0,
                        0,
                    ]),
                },
                im: BLS381 {
                    val: U512([
                        0xe5ac7d055d042b7e,
                        0x334cf11213945d57,
                        0xb5da61bbdc7f5049,
                        0x596bd0d09920b61a,
                        0x7dacd3a088274f65,
                        0x13e02b6052719f60,
                        0,
                        0,
                    ]),
                },
            },
            y: Fp2 {
                re: BLS381 {
                    val: U512([
                        0xe193548608b82801,
                        0x923ac9cc3baca289,
                        0x6d429a695160d12c,
                        0xadfd9baa8cbdd3a7,
                        0x8cc9cdc6da2e351a,
                        0x0ce5d527727d6e11,
                        0,
                        0,
                    ]),
                },
                im: BLS381 {
                    val: U512([
                        0xaaa9075ff05f79be,
                        0x3f370d275cec1da1,
                        0x267492ab572e99ab,
                        0xcb3e287e85a763af,
                        0x32acd2b02bc28b99,
                        0x0606c4a02ea734cc,
                        0,
                        0,
                    ]),
                },
            },
        };
    }

    /// Deserializes a sequence of bytes into a BLS12-381 G1 element in affine
    /// coordinates. Follows the procedure defined in `octets_to_point` of
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#appendix-A>,
    /// based on zkcrypto/bls12_381 serialization design notes available at
    /// <https://github.com/zkcrypto/bls12_381/blob/main/src/notes/serialization.rs>.
    pub(crate) fn g1_from_bytes(bytes: &[u8; 48]) -> Result<CurveAff<BLS381>> {
        // Obtain the three flags from the start of the byte sequence
        let compression_flag_set = ((bytes[0] >> 7) & 1) != 0;
        let infinity_flag_set = ((bytes[0] >> 6) & 1) != 0;
        let sort_flag_set = ((bytes[0] >> 5) & 1) != 0;

        // Attempt to obtain the x-coordinate
        let x = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);

            // Mask away the flag bits
            tmp[0] &= 0b0001_1111;

            BLS381 {
                val: U512::from_big_endian(&tmp),
            }
        };

        if x.val > BLS_BASE {
            return Err(anyhow!("X coordinate is larger than modulus."));
        }

        if infinity_flag_set {
            if !(
                compression_flag_set & // Compression flag should be set
                (!sort_flag_set) & // Sort flag should not be set
                x.val.is_zero()
                // The x-coordinate should be zero
            ) {
                return Err(anyhow!("Byte flags are contradictory"));
            }

            return Ok(CurveAff::<BLS381>::unit());
        }

        // Recover a y-coordinate given x with y = sqrt(x^3 + 4).
        if let Ok(mut y) = ((x * x * x) + B_G1).sqrt() {
            // Switch to the correct y-coordinate if necessary.

            if y.lexicographically_largest() ^ sort_flag_set {
                y = -y;
            }

            if infinity_flag_set | !compression_flag_set {
                return Err(anyhow!("Byte flags are contradictory"));
            }

            Ok(CurveAff::<BLS381> { x, y })
        } else {
            Err(anyhow!("This point is not on the curve."))
        }
    }

    // The optimal Ate pairing takes a point each from the curve and its twist and
    // outputs an Fp12 element.
    pub(crate) fn ate_optim(p: CurveAff<BLS381>, q: CurveAff<Fp2<BLS381>>) -> Fp12<BLS381> {
        let miller_output = miller_loop(p, q);
        final_exponent(miller_output)
    }

    /// Miller loop for the optimal Ate pairing, which computes $f_{u,Q}(P)$
    /// with the accumulator as a point on the twist, before exponentiating
    /// by $(p^12 - 1)/r$ with $r$ the order of the multiplicative target group.
    pub(crate) fn miller_loop(p: CurveAff<BLS381>, q: CurveAff<Fp2<BLS381>>) -> Fp12<BLS381> {
        let mut r = CurveProj::<Fp2<BLS381>> {
            x: q.x,
            y: q.y,
            z: Fp2::<BLS381>::UNIT,
        };
        let mut acc: Fp12<BLS381> = Fp12::<BLS381>::UNIT;

        let mut found_one = false;
        for i in (0..64).rev().map(|b| (((X_GENERATOR >> 1) >> b) & 1) == 1) {
            if !found_one {
                found_one = i;
                continue;
            }
            let coeffs = doubling_step(&mut r);
            acc = ell(acc, &coeffs, &p);

            if i {
                let coeffs = addition_step(&mut r, &q);
                acc = ell(acc, &coeffs, &p);
            }

            acc = acc * acc;
        }

        let coeffs = doubling_step(&mut r);
        acc = ell(acc, &coeffs, &p);

        acc.conj() // X_GENERATOR is negative
    }

    fn ell(
        f: Fp12<BLS381>,
        coeffs: &(Fp2<BLS381>, Fp2<BLS381>, Fp2<BLS381>),
        p: &CurveAff<BLS381>,
    ) -> Fp12<BLS381> {
        let mut c0 = coeffs.0;
        let mut c1 = coeffs.1;

        c0.re = c0.re * p.y;
        c0.im = c0.im * p.y;

        c1.re = c1.re * p.x;
        c1.im = c1.im * p.x;

        f.mul_by_014(coeffs.2, c1, c0)
    }

    fn doubling_step(r: &mut CurveProj<Fp2<BLS381>>) -> (Fp2<BLS381>, Fp2<BLS381>, Fp2<BLS381>) {
        // Adaptation of Algorithm 26, https://eprint.iacr.org/2010/354.pdf
        let tmp0 = r.x * r.x;
        let tmp1 = r.y * r.y;
        let tmp2 = tmp1 * tmp1;
        let tmp3 = (tmp1 + r.x) * (tmp1 + r.x) - tmp0 - tmp2;
        let tmp3 = tmp3 + tmp3;
        let tmp4 = tmp0 + tmp0 + tmp0;
        let tmp6 = r.x + tmp4;
        let tmp5 = tmp4 * tmp4;
        let z_sq = r.z * r.z;
        r.x = tmp5 - tmp3 - tmp3;
        r.z = (r.z + r.y) * (r.z + r.y) - tmp1 - z_sq;
        r.y = (tmp3 - r.x) * tmp4;
        let tmp2 = tmp2 + tmp2;
        let tmp2 = tmp2 + tmp2;
        let tmp2 = tmp2 + tmp2;
        r.y = r.y - tmp2;
        let tmp3 = tmp4 * z_sq;
        let tmp3 = tmp3 + tmp3;
        let tmp3 = -tmp3;
        let tmp6 = tmp6 * tmp6 - tmp0 - tmp5;
        let tmp1 = tmp1 + tmp1;
        let tmp1 = tmp1 + tmp1;
        let tmp6 = tmp6 - tmp1;
        let tmp0 = r.z * z_sq;
        let tmp0 = tmp0 + tmp0;

        (tmp0, tmp3, tmp6)
    }

    fn addition_step(
        r: &mut CurveProj<Fp2<BLS381>>,
        q: &CurveAff<Fp2<BLS381>>,
    ) -> (Fp2<BLS381>, Fp2<BLS381>, Fp2<BLS381>) {
        // Adaptation of Algorithm 27, https://eprint.iacr.org/2010/354.pdf
        let z_sq = r.z * r.z;
        let y_sq = q.y * q.y;
        let t0 = z_sq * q.x;
        let t1 = ((q.y + r.z) * (q.y + r.z) - y_sq - z_sq) * z_sq;
        let t2 = t0 - r.x;
        let t3 = t2 * t2;
        let t4 = t3 + t3;
        let t4 = t4 + t4;
        let t5 = t4 * t2;
        let t6 = t1 - r.y - r.y;
        let t9 = t6 * q.x;
        let t7 = t4 * r.x;
        r.x = t6 * t6 - t5 - t7 - t7;
        r.z = (r.z + t2) * (r.z + t2) - z_sq - t3;
        let t10 = q.y + r.z;
        let t8 = (t7 - r.x) * t6;
        let t0 = r.y * t5;
        let t0 = t0 + t0;
        r.y = t8 - t0;
        let t10 = t10 * t10 - y_sq;
        let zt_sq = r.z * r.z;
        let t10 = t10 - zt_sq;
        let t9 = t9 + t9 - t10;
        let t10 = r.z + r.z;
        let t6 = -t6;
        let t1 = t6 + t6;

        (t10, t1, t9)
    }

    /// The output y of the miller loop is not an invariant,
    /// but one gets an invariant by raising y to the power
    ///     (p^12 - 1)/N = (p^6 - 1)(p^2 + 1)(p^4 - p^2 + 1)/N
    /// where N is the cyclic group order of the curve.
    ///
    /// See section 5 of <https://eprint.iacr.org/2020/875.pdf>.
    pub(crate) fn final_exponent(f: Fp12<BLS381>) -> Fp12<BLS381> {
        let mut t0 = f.frob(6);
        let mut t1 = f.inv();
        let mut t2 = t0 * t1;
        t1 = t2;
        t2 = t2.frob(2);
        t2 = t2 * t1;
        t1 = cyclotomic_square(t2).conj();
        let mut t3 = cyclotomic_exp(t2);
        let mut t4 = cyclotomic_square(t3);
        let mut t5 = t1 * t3;
        t1 = cyclotomic_exp(t5);
        t0 = cyclotomic_exp(t1);
        let mut t6 = cyclotomic_exp(t0);
        t6 = t6 * t4;
        t4 = cyclotomic_exp(t6);
        t5 = t5.conj();
        t4 = t4 * t5;
        t4 = t4 * t2;
        t5 = t2.conj();
        t1 = t1 * t2;
        t1 = t1.frob(3);
        t6 = t6 * t5;
        t6 = t6.frob(1);
        t3 = t3 * t0;
        t3 = t3.frob(2);
        t3 = t3 * t1;
        t3 = t3 * t6;
        t3 * t4
    }

    fn fp4_square(a: Fp2<BLS381>, b: Fp2<BLS381>) -> (Fp2<BLS381>, Fp2<BLS381>) {
        let t0 = a * a;
        let t1 = b * b;
        let mut t2 = t1.mul_adj();
        let c0 = t2 + t0;
        t2 = a + b;
        t2 = t2 * t2 - t0;
        let c1 = t2 - t1;

        (c0, c1)
    }

    // Adaptation of Algorithm 5.5.4, Guide to Pairing-Based Cryptography
    // Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions
    // <https://eprint.iacr.org/2009/565.pdf>.
    fn cyclotomic_square(f: Fp12<BLS381>) -> Fp12<BLS381> {
        let mut z0 = f.z0.t0;
        let mut z4 = f.z0.t1;
        let mut z3 = f.z0.t2;
        let mut z2 = f.z1.t0;
        let mut z1 = f.z1.t1;
        let mut z5 = f.z1.t2;

        let (t0, t1) = fp4_square(z0, z1);

        // For A
        z0 = t0 - z0;
        z0 = z0 + z0 + t0;

        z1 = t1 + z1;
        z1 = z1 + z1 + t1;

        let (mut t0, t1) = fp4_square(z2, z3);
        let (t2, t3) = fp4_square(z4, z5);

        // For C
        z4 = t0 - z4;
        z4 = z4 + z4 + t0;

        z5 = t1 + z5;
        z5 = z5 + z5 + t1;

        // For B
        t0 = t3.mul_adj();
        z2 = t0 + z2;
        z2 = z2 + z2 + t0;

        z3 = t2 - z3;
        z3 = z3 + z3 + t2;

        Fp12::<BLS381> {
            z0: Fp6::<BLS381> {
                t0: z0,
                t1: z4,
                t2: z3,
            },
            z1: Fp6::<BLS381> {
                t0: z2,
                t1: z1,
                t2: z5,
            },
        }
    }

    fn cyclotomic_exp(f: Fp12<BLS381>) -> Fp12<BLS381> {
        let mut tmp = Fp12::<BLS381>::UNIT;

        let mut found_one = false;
        for i in (0..64).rev().map(|b| ((X_GENERATOR >> b) & 1) == 1) {
            if found_one {
                tmp = cyclotomic_square(tmp)
            } else {
                found_one = i;
            }

            if i {
                tmp = tmp * f;
            }
        }

        tmp.conj()
    }

    /// The value used to generate both scalar and base fields of BLS12-381.
    /// Note that `x` is negative, and the Miller loop hence require a final
    /// conjugation in Fp12.
    const X_GENERATOR: u64 = 0xd201000000010000;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_tower::BN254;

    #[test]
    fn test_bls_pairing() {
        let mut rng = rand::thread_rng();
        let mut acc = 0_i32;
        let mut running_product = Fp12::<BLS381>::UNIT;
        for _ in 0..5 {
            let m = rng.gen_range(-8..8);
            let n = rng.gen_range(-8..8);
            if m * n == 0 {
                continue;
            }
            acc -= m * n;

            let p = CurveAff::<BLS381>::int(m);
            let q = CurveAff::<Fp2<BLS381>>::int(n);
            running_product = running_product * bls381::ate_optim(p, q);
        }

        // Finally, multiply by the accumulated inverse and check this matches the
        // expected value.
        let p = CurveAff::<BLS381>::int(acc);
        let q = CurveAff::<Fp2<BLS381>>::GENERATOR;
        running_product = running_product * bls381::ate_optim(p, q);

        let expected = if acc == 0 {
            Fp12::<BLS381>::ZERO
        } else {
            Fp12::<BLS381>::UNIT
        };

        assert_eq!(running_product, expected);
    }

    #[test]
    fn test_bn_pairing() {
        let mut rng = rand::thread_rng();
        let mut acc = 0_i32;
        let mut running_product = Fp12::<BN254>::UNIT;
        for _ in 0..5 {
            let m = rng.gen_range(-8..8);
            let n = rng.gen_range(-8..8);
            if m * n == 0 {
                continue;
            }
            acc -= m * n;

            let p = CurveAff::<BN254>::int(m);
            let q = CurveAff::<Fp2<BN254>>::int(n);
            running_product = running_product * bn254::tate(p, q);
        }

        // Finally, multiply by the accumulated inverse and check this matches the
        // expected value.
        let p = CurveAff::<BN254>::int(acc);
        let q = CurveAff::<Fp2<BN254>>::GENERATOR;
        running_product = running_product * bn254::tate(p, q);

        let expected = if acc == 0 {
            Fp12::<BN254>::ZERO
        } else {
            Fp12::<BN254>::UNIT
        };

        assert_eq!(running_product, expected);
    }
}
