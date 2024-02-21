use core::ops::{Add, Mul, Neg};

use ethereum_types::{U256, U512};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::Rng;

use crate::extension_tower::{FieldExt, Fp12, Fp2, Fp6, Stack, BLS381, BN254};

#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) struct Curve<T>
where
    T: FieldExt,
{
    pub x: T,
    pub y: T,
}

impl<T: FieldExt> Curve<T> {
    pub(crate) const fn unit() -> Self {
        Curve {
            x: T::ZERO,
            y: T::ZERO,
        }
    }
}

impl<T: FieldExt + Stack> Stack for Curve<T> {
    const SIZE: usize = 2 * T::SIZE;

    fn to_stack(&self) -> Vec<U256> {
        let mut stack = self.x.to_stack();
        stack.extend(self.y.to_stack());
        stack
    }

    fn from_stack(stack: &[U256]) -> Self {
        Curve {
            x: T::from_stack(&stack[0..T::SIZE]),
            y: T::from_stack(&stack[T::SIZE..2 * T::SIZE]),
        }
    }
}

impl<T> Curve<T>
where
    T: FieldExt,
    Curve<T>: CyclicGroup,
{
    pub(crate) fn int(z: i32) -> Self {
        Curve::<T>::GENERATOR * z
    }
}

impl<T> Distribution<Curve<T>> for Standard
where
    T: FieldExt,
    Curve<T>: CyclicGroup,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Curve<T> {
        Curve::<T>::GENERATOR * rng.gen::<i32>()
    }
}

/// Standard addition formula for elliptic curves, restricted to the cases  
/// <https://en.wikipedia.org/wiki/Elliptic_curve#Algebraic_interpretation>
impl<T: FieldExt> Add for Curve<T> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        if self == Curve::<T>::unit() {
            return other;
        }
        if other == Curve::<T>::unit() {
            return self;
        }
        if self == -other {
            return Curve::<T>::unit();
        }
        let m = if self == other {
            T::new(3) * self.x * self.x / (T::new(2) * self.y)
        } else {
            (other.y - self.y) / (other.x - self.x)
        };
        let x = m * m - (self.x + other.x);
        Curve {
            x,
            y: m * (self.x - x) - self.y,
        }
    }
}

impl<T: FieldExt> Neg for Curve<T> {
    type Output = Curve<T>;

    fn neg(self) -> Self {
        Curve {
            x: self.x,
            y: -self.y,
        }
    }
}

pub trait CyclicGroup {
    const GENERATOR: Self;
}

impl<T> Mul<i32> for Curve<T>
where
    T: FieldExt,
    Curve<T>: CyclicGroup,
{
    type Output = Curve<T>;

    fn mul(self, other: i32) -> Self {
        if other == 0 {
            return Curve::<T>::unit();
        }
        if self == Curve::<T>::unit() {
            return Curve::<T>::unit();
        }

        let mut x: Curve<T> = self;
        if other.is_negative() {
            x = -x;
        }
        let mut result = Curve::<T>::unit();

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
pub mod bn254 {
    use super::*;

    /// The BN curve consists of pairs
    ///     (x, y): (BN254, BN254) | y^2 = x^3 + 3
    // with generator given by (1, 2)
    impl CyclicGroup for Curve<BN254> {
        const GENERATOR: Curve<BN254> = Curve {
            x: BN254 { val: U256::one() },
            y: BN254 {
                val: U256([2, 0, 0, 0]),
            },
        };
    }

    /// The twisted curve consists of pairs
    ///     (x, y): (Fp2<BN254>, Fp2<BN254>) | y^2 = x^3 + 3/(9 + i)
    /// with generator given as follows
    impl CyclicGroup for Curve<Fp2<BN254>> {
        const GENERATOR: Curve<Fp2<BN254>> = Curve {
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

    // The tate pairing takes a point each from the curve and its twist and outputs
    // an Fp12 element.
    pub(crate) fn tate(p: Curve<BN254>, q: Curve<Fp2<BN254>>) -> Fp12<BN254> {
        let miller_output = miller_loop(p, q);
        final_exponent(miller_output)
    }

    /// Standard code for miller loop, can be found on page 99 at this url:
    /// <https://static1.squarespace.com/static/5fdbb09f31d71c1227082339/t/5ff394720493bd28278889c6/1609798774687/PairingsForBeginners.pdf#page=107>
    /// where BN_EXP is a hardcoding of the array of Booleans that the loop
    /// traverses.
    pub(crate) fn miller_loop(p: Curve<BN254>, q: Curve<Fp2<BN254>>) -> Fp12<BN254> {
        let mut r = p;
        let mut acc: Fp12<BN254> = Fp12::<BN254>::UNIT;
        let mut line: Fp12<BN254>;

        for i in BN_EXP {
            line = tangent(r, q);
            r = r + r;
            acc = line * acc * acc;
            if i {
                line = cord(p, r, q);
                r = r + p;
                acc = line * acc;
            }
        }
        acc
    }

    /// The sloped line function for doubling a point.
    pub(crate) fn tangent(p: Curve<BN254>, q: Curve<Fp2<BN254>>) -> Fp12<BN254> {
        let cx = -BN254::new(3) * p.x * p.x;
        let cy = BN254::new(2) * p.y;
        sparse_embed(p.y * p.y - BN254::new(9), q.x * cx, q.y * cy)
    }

    /// The sloped line function for adding two points.
    pub(crate) fn cord(p1: Curve<BN254>, p2: Curve<BN254>, q: Curve<Fp2<BN254>>) -> Fp12<BN254> {
        let cx = p2.y - p1.y;
        let cy = p1.x - p2.x;
        sparse_embed(p1.y * p2.x - p2.y * p1.x, q.x * cx, q.y * cy)
    }

    /// The tangent and cord functions output sparse Fp12 elements.
    /// This map embeds the nonzero coefficients into an Fp12.
    pub(crate) const fn sparse_embed(g000: BN254, g01: Fp2<BN254>, g11: Fp2<BN254>) -> Fp12<BN254> {
        let g0 = Fp6 {
            t0: Fp2 {
                re: g000,
                im: BN254::ZERO,
            },
            t1: g01,
            t2: Fp2::<BN254>::ZERO,
        };

        let g1 = Fp6 {
            t0: Fp2::<BN254>::ZERO,
            t1: g11,
            t2: Fp2::<BN254>::ZERO,
        };

        Fp12 { z0: g0, z1: g1 }
    }

    pub(crate) fn gen_fp12_sparse<R: Rng + ?Sized>(rng: &mut R) -> Fp12<BN254> {
        sparse_embed(
            rng.gen::<BN254>(),
            rng.gen::<Fp2<BN254>>(),
            rng.gen::<Fp2<BN254>>(),
        )
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

    // The following constants are defined above get_custom_powers
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

pub mod bls12 {
    use super::*;

    /// The BLS curve consists of pairs
    ///     (x, y): (BLS381, BLS381) | y^2 = x^3 + 4
    // with generator given by
    //      x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
    //      y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
    impl CyclicGroup for Curve<BLS381> {
        const GENERATOR: Curve<BLS381> = Curve {
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
    ///     (x, y): (Fp2<BLS381>, Fp2<BLS381>) | y^2 = x^3 + 4/(i + 1)
    /// with generator given by
    //      x = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
    //          + 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 * i
    //      y = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905
    //          + 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582 * i
    impl CyclicGroup for Curve<Fp2<BLS381>> {
        const GENERATOR: Curve<Fp2<BLS381>> = Curve {
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

    // The tate pairing takes a point each from the curve and its twist and outputs
    // an Fp12 element.
    pub(crate) fn tate(p: Curve<BLS381>, q: Curve<Fp2<BLS381>>) -> Fp12<BLS381> {
        let miller_output = miller_loop(p, q);
        final_exponent(miller_output)
    }

    /// Standard code for miller loop, can be found on page 99 at this url:
    /// <https://static1.squarespace.com/static/5fdbb09f31d71c1227082339/t/5ff394720493bd28278889c6/1609798774687/PairingsForBeginners.pdf#page=107>
    /// where BLS_EXP is a hardcoding of the array of Booleans that the loop
    /// traverses.
    pub(crate) fn miller_loop(p: Curve<BLS381>, q: Curve<Fp2<BLS381>>) -> Fp12<BLS381> {
        let mut r = p;
        let mut acc: Fp12<BLS381> = Fp12::<BLS381>::UNIT;
        let mut line: Fp12<BLS381>;

        for i in BLS_EXP {
            line = tangent(r, q);
            r = r + r;
            acc = line * acc * acc;
            if i {
                line = cord(p, r, q);
                r = r + p;
                acc = line * acc;
            }
        }
        acc
    }

    /// The sloped line function for doubling a point.
    pub(crate) fn tangent(p: Curve<BLS381>, q: Curve<Fp2<BLS381>>) -> Fp12<BLS381> {
        let cx = -BLS381::new(3) * p.x * p.x;
        let cy = BLS381::new(2) * p.y;
        sparse_embed(p.y * p.y - BLS381::new(9), q.x * cx, q.y * cy)
    }

    /// The sloped line function for adding two points.
    pub(crate) fn cord(
        p1: Curve<BLS381>,
        p2: Curve<BLS381>,
        q: Curve<Fp2<BLS381>>,
    ) -> Fp12<BLS381> {
        let cx = p2.y - p1.y;
        let cy = p1.x - p2.x;
        sparse_embed(p1.y * p2.x - p2.y * p1.x, q.x * cx, q.y * cy)
    }

    /// The tangent and cord functions output sparse Fp12 elements.
    /// This map embeds the nonzero coefficients into an Fp12.
    pub(crate) const fn sparse_embed(
        g000: BLS381,
        g01: Fp2<BLS381>,
        g11: Fp2<BLS381>,
    ) -> Fp12<BLS381> {
        let g0 = Fp6 {
            t0: Fp2 {
                re: g000,
                im: BLS381::ZERO,
            },
            t1: g01,
            t2: Fp2::<BLS381>::ZERO,
        };

        let g1 = Fp6 {
            t0: Fp2::<BLS381>::ZERO,
            t1: g11,
            t2: Fp2::<BLS381>::ZERO,
        };

        Fp12 { z0: g0, z1: g1 }
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
    ///     (p^4 - p^2 + 1)/N = (a3)p^3 + (a2)p^2 + (a1)p + a0
    /// where 0 < a0, a1, a2, a3 < p.
    /// Then the final power is given by
    ///     y = (y^a3)_3 * (y^a2)_2 * (y^a1)_1 * (y^a0).
    ///
    /// The values a3, a2, a1, a0 taken here are:
    ///     a3 = 0x396c8c005555e1568c00aaab0000aaaa
    ///     a2 = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf38158e5c24aff488b27c92a7df51e7fe1ea8ffff5554aaab
    ///     a1 = 0x26a48d1bb889d46dc49f25e1a737f5e29d586d584eacaaaa73ffffffffff5554
    ///     a0 = 0x1a0111ea397fe69a2b688550f8cebd66f7a34148de09bf34665a045e22ec661f33813d5206aa1800aaaa0000aaaaaaac
    pub(crate) fn final_exponent(f: Fp12<BLS381>) -> Fp12<BLS381> {
        let mut y = f.frob(6) / f;
        y = y.frob(2) * y;
        let (y_a3, y_a2, y_a1, y_a0) = get_custom_powers(y);
        y_a3.frob(3) * y_a2.frob(2) * y_a1.frob(1) * y_a0
    }

    /// We compute y^a3, y^a2, y^a1, y^a0.
    ///
    /// a3, a2, a1 and a0 are represented in *little endian* binary.
    fn get_custom_powers(
        f: Fp12<BLS381>,
    ) -> (Fp12<BLS381>, Fp12<BLS381>, Fp12<BLS381>, Fp12<BLS381>) {
        let mut y0: Fp12<BLS381> = Fp12::<BLS381>::UNIT;
        let mut y1: Fp12<BLS381> = Fp12::<BLS381>::UNIT;
        let mut y2: Fp12<BLS381> = Fp12::<BLS381>::UNIT;
        let mut y3: Fp12<BLS381> = Fp12::<BLS381>::UNIT;

        // proceed via standard squaring algorithm for exponentiation

        // compute y3
        let mut sq: Fp12<BLS381> = f;
        for bit in BLS_A3 {
            if bit {
                y3 = y3 * sq;
            }
            sq = sq * sq;
        }

        // compute y2 and y0
        let mut sq: Fp12<BLS381> = f;
        for (bit_a2, bit_a0) in BLS_A2.iter().zip(BLS_A0) {
            if *bit_a2 {
                y2 = y2 * sq;
            }
            if bit_a0 {
                y0 = y0 * sq;
            }
            sq = sq * sq;
        }

        // compute y1
        let mut sq: Fp12<BLS381> = f;
        for bit in BLS_A1 {
            if bit {
                y1 = y1 * sq;
            }
            sq = sq * sq;
        }

        // return y^a3 = y3, y^a2 = y2, y^a1 = y2, y^a0 = y0
        (y3, y2, y1, y0)
    }

    const BLS_EXP: [bool; 254] = [
        true, true, false, false, true, true, true, true, true, false, true, true, false, true,
        true, false, true, false, false, true, true, true, false, true, false, true, false, false,
        true, true, false, false, true, false, true, false, false, true, true, false, false, true,
        true, true, false, true, false, true, true, true, true, true, false, true, false, true,
        false, false, true, false, false, false, false, false, true, true, false, false, true,
        true, false, false, true, true, true, false, false, true, true, true, false, true, true,
        false, false, false, false, false, false, false, true, false, false, false, false, false,
        false, false, true, false, false, true, true, false, true, false, false, false, false,
        true, true, true, false, true, true, false, false, false, false, false, false, false,
        false, true, false, true, false, true, false, true, false, false, true, true, true, false,
        true, true, true, true, false, true, true, false, true, false, false, true, false, false,
        false, false, false, false, false, false, true, false, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, false, false, true, false, true,
        true, false, true, true, true, true, true, true, true, true, true, false, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true, true, true, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false,
    ];

    // The following constants are defined above get_custom_powers.
    const BLS_A3: [bool; 126] = [
        false, true, false, true, false, true, false, true, false, true, false, true, false, true,
        false, true, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, true, true, false, true, false, true, false, true,
        false, true, false, true, false, true, false, true, false, false, false, false, false,
        false, false, false, false, false, true, true, false, false, false, true, false, true,
        true, false, true, false, true, false, true, false, false, false, false, true, true, true,
        true, false, true, false, true, false, true, false, true, false, true, false, true, false,
        true, false, false, false, false, false, false, false, false, false, false, false, true,
        true, false, false, false, true, false, false, true, true, false, true, true, false, true,
        false, false, true, true, true,
    ];
    const BLS_A2: [bool; 381] = [
        true, true, false, true, false, true, false, true, false, true, false, true, false, true,
        false, true, false, false, true, false, true, false, true, false, true, false, true, false,
        true, false, true, false, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, false, false, false, true, false, true, false, true, false,
        true, true, true, true, false, false, false, false, true, true, true, true, true, true,
        true, true, true, true, false, false, true, true, true, true, false, false, false, true,
        false, true, false, true, true, true, true, true, false, true, true, true, true, true,
        false, false, true, false, true, false, true, false, false, true, false, false, true,
        false, false, true, true, true, true, true, false, false, true, false, false, true, true,
        false, true, false, false, false, true, false, false, false, true, false, false, true,
        false, true, true, true, true, true, true, true, true, false, true, false, true, false,
        false, true, false, false, true, false, false, false, false, true, true, true, false, true,
        false, false, true, true, true, false, false, false, true, true, false, true, false, true,
        false, false, false, false, false, false, true, true, true, false, false, true, true, true,
        true, true, true, false, true, false, true, false, false, true, false, false, false, true,
        false, true, false, false, false, false, true, true, true, false, false, true, true, true,
        true, false, false, true, false, false, false, false, true, true, true, false, true, false,
        false, true, false, true, true, true, false, true, true, true, false, false, false, true,
        false, false, true, true, false, true, true, true, false, true, false, true, true, false,
        false, true, true, false, true, false, true, true, true, false, true, false, false, true,
        false, true, true, false, false, false, false, true, false, false, true, true, false, true,
        true, false, true, true, true, true, false, false, true, false, true, true, true, false,
        true, true, false, false, false, true, true, false, true, false, false, true, false, false,
        true, false, true, true, false, false, true, false, true, true, false, false, true, true,
        true, true, true, true, true, true, true, true, false, true, false, false, true, true,
        true, false, false, false, true, false, true, false, true, true, true, true, false, false,
        false, true, false, false, false, true, false, false, false, false, false, false, false,
        false, true, false, true, true,
    ];
    const BLS_A1: [bool; 254] = [
        false, false, true, false, true, false, true, false, true, false, true, false, true, false,
        true, false, true, true, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
        true, true, true, true, true, true, true, true, true, true, true, true, true, true, false,
        false, true, true, true, false, false, true, false, true, false, true, false, true, false,
        true, false, true, false, true, false, true, false, false, true, true, false, true, false,
        true, false, true, true, true, false, false, true, false, false, false, false, true, true,
        false, true, false, true, false, true, true, false, true, true, false, false, false, false,
        true, true, false, true, false, true, false, true, true, true, false, false, true, false,
        true, false, false, false, true, true, true, true, false, true, false, true, true, true,
        true, true, true, true, false, true, true, false, false, true, true, true, false, false,
        true, false, true, true, false, false, false, false, true, true, true, true, false, true,
        false, false, true, false, false, true, true, true, true, true, false, false, true, false,
        false, true, false, false, false, true, true, true, false, true, true, false, true, true,
        false, false, false, true, false, true, false, true, true, true, false, false, true, false,
        false, false, true, false, false, false, true, true, true, false, true, true, true, false,
        true, true, false, false, false, true, false, true, true, false, false, false, true, false,
        false, true, false, false, true, false, true, false, true, true, false, false, true,
    ];
    const BLS_A0: [bool; 381] = [
        false, false, true, true, false, true, false, true, false, true, false, true, false, true,
        false, true, false, true, false, true, false, true, false, true, false, true, false, true,
        false, true, false, true, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, true, false, true, false, true,
        false, true, false, true, false, true, false, true, false, true, false, false, false,
        false, false, false, false, false, false, false, false, true, true, false, false, false,
        false, true, false, true, false, true, false, true, false, true, true, false, false, false,
        false, false, false, true, false, false, true, false, true, false, true, false, true, true,
        true, true, false, false, true, false, false, false, false, false, false, true, true, true,
        false, false, true, true, false, false, true, true, true, true, true, false, false, false,
        false, true, true, false, false, true, true, false, false, false, true, true, false, true,
        true, true, false, true, false, false, false, true, false, false, false, true, true, true,
        true, false, true, false, false, false, true, false, false, false, false, false, false,
        true, false, true, true, false, true, false, false, true, true, false, false, true, true,
        false, false, false, true, false, true, true, false, false, true, true, true, true, true,
        true, false, true, true, false, false, true, false, false, false, false, false, true, true,
        true, true, false, true, true, false, false, false, true, false, false, true, false, true,
        false, false, false, false, false, true, false, true, true, false, false, false, true,
        false, true, true, true, true, false, true, true, true, true, false, true, true, false,
        false, true, true, false, true, false, true, true, true, true, false, true, false, true,
        true, true, false, false, true, true, false, false, false, true, true, true, true, true,
        false, false, false, false, true, false, true, false, true, false, true, false, false,
        false, false, true, false, false, false, true, false, true, true, false, true, true, false,
        true, false, true, false, false, false, true, false, true, true, false, false, true, false,
        true, true, false, false, true, true, true, true, true, true, true, true, true, true,
        false, true, false, false, true, true, true, false, false, false, true, false, true, false,
        true, true, true, true, false, false, false, true, false, false, false, true, false, false,
        false, false, false, false, false, false, true, false, true, true,
    ];
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_bls12_pairing() {
        let x0 = -bls12::tate(Curve::<BLS381>::GENERATOR, Curve::<Fp2<BLS381>>::GENERATOR);
        let x1 = bls12::tate(-Curve::<BLS381>::GENERATOR, Curve::<Fp2<BLS381>>::GENERATOR);
        let x2 = bls12::tate(Curve::<BLS381>::GENERATOR, -Curve::<Fp2<BLS381>>::GENERATOR);

        println!(
            "{:?}",
            bls12::tate(-Curve::<BLS381>::GENERATOR, Curve::<Fp2<BLS381>>::GENERATOR)
                * bls12::tate(Curve::<BLS381>::GENERATOR, Curve::<Fp2<BLS381>>::GENERATOR)
        );
        // TODO: Fix test
        // assert_eq!(x0, x1);
        // assert_eq!(x1, x2);
    }

    #[test]
    fn test_bn_pairing() {
        let x0 = -bn254::tate(Curve::<BN254>::GENERATOR, Curve::<Fp2<BN254>>::GENERATOR);
        let x1 = bn254::tate(-Curve::<BN254>::GENERATOR, Curve::<Fp2<BN254>>::GENERATOR);
        let x2 = bn254::tate(Curve::<BN254>::GENERATOR, -Curve::<Fp2<BN254>>::GENERATOR);

        println!(
            "{:?}",
            bn254::tate(-Curve::<BN254>::GENERATOR, Curve::<Fp2<BN254>>::GENERATOR)
                * bn254::tate(Curve::<BN254>::GENERATOR, Curve::<Fp2<BN254>>::GENERATOR)
        );

        // TODO: Fix test
        // assert_eq!(x0, x1);
        // assert_eq!(x1, x2);
    }
}
