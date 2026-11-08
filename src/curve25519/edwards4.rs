//! Edwards point arithmetic four field elements at a time, for verifying
//! signatures (in variable time: every input is public).
//!
//! A point's extended coordinates (X, Y, Z, T) occupy the four lanes of an
//! [`F4`] (radix 2^25.5 in AVX2 registers, see [`ladder`](mod@super::ladder)), so
//! a doubling is a 4-way squaring and a 4-way multiplication, and an addition
//! two 4-way multiplications. Zen 3 issues a 64-bit MULX every other cycle
//! but a 256-bit VPMULUDQ every cycle, so this is about 1.5 times as fast as
//! the scalar formulas of [`edwards`](super::edwards).
//!
//! The formulas are those of Hisil, Wong, Carter and Dawson ("Twisted Edwards
//! curves revisited", 2008) for a = -1, arranged for four lanes as in
//! curve25519-dalek's AVX2 backend:
//!
//! ```text
//! double: (S1, S2, S3, S4) = (X^2, Y^2, Z^2, (X + Y)^2)
//!         (S5, S6, S8, S9) = (S1 + S2, S1 - S2, S1 - S2 + 2 S3, S1 + S2 - S4)
//!         2P = (S8, S5, S8, S5) * (S9, S6, S6, S9)
//! add:    (A, B, C, D) = (Y1 - X1, Y1 + X1, T1, Z1) * Q
//!         (E, H, F, G) = (B - A, B + A, D - C, D + C)
//!         P + Q = (E, G, G, E) * (F, H, F, H)
//! ```
//!
//! For P - Q, swapping the first two lanes of the first factor gives the
//! (B, A, -C, D) of P + (-Q), from which (E, H, F, G) take as many
//! operations, so the tables hold only positive multiples.
//!
//! Q is a cached point (λ(Y - X), λ(Y + X), -2·121665 T, 2λZ) with
//! λ = 121666: scaling every coordinate by λ leaves the projective result
//! alone and turns the multiplication by 2d = -2·121665/121666 into one by
//! small constants. (Its T and Z lanes are swapped like those of the first
//! factor, so that the product comes out in the order the next step needs.)
//!
//! Bounds: the 4-way multiplication takes normalized limbs and sums or
//! differences (with 2p added) of two normalized values. In an addition every
//! operand is one of those. In a doubling the squaring does a single carry
//! round (its limbs stay below 2^26 + 19 * 2^36), so (S5, S6, S8, S9) are
//! computed with 2^15 p instead of 2p and get one carry round, which leaves
//! them below 2^26 + 2^22; the tests check this with extreme limbs.

use super::base_table::{B_NAF_WIDTH, ODD_MULTIPLES_4WAY};
use super::edwards::{Point, naf};
use super::field::barrier_vec;
use super::ladder::{F4, TWO_P, from_lanes, mul, square, times19, times19_vec, to_limbs};
use super::scalar::Scalar;
use core::arch::x86_64::*;

/// Blend masks (32-bit elements) for each 64-bit lane.
const LANE_A: i32 = 0x03;
const LANE_B: i32 = 0x0c;
const LANE_C: i32 = 0x30;
const LANE_D: i32 = 0xc0;

/// 2^15 p in radix 2^25.5, above every limb of a squaring's output.
const P_2_15: [[i64; 2]; 5] = {
    let mut k = [[((1 << 26) - 1) << 15, ((1 << 25) - 1) << 15]; 5];
    k[0][0] = ((1 << 26) - 19) << 15;
    k
};

/// A point (X, Y, Z, T) in the lanes of an `F4`, normalized.
#[derive(Clone, Copy)]
struct Point4(F4);

/// A cached point (see the module docs) and 19 times it.
#[derive(Clone, Copy)]
#[repr(C)]
struct Cached4 {
    q: F4,
    q19: F4,
}

/// Buffers for the operands of the 4-way multiplications.
struct Scratch {
    a: F4,
    a19: F4,
    b: F4,
    c: F4,
    c19: F4,
}

/// `[a]P + [b]B` in variable time: interleaved w-NAFs, of width 5 for `a`
/// (with the odd multiples of P computed here) and `B_NAF_WIDTH` for `b`
/// (with those of B precomputed).
pub(super) fn mul_vartime(p: &Point, a: &Scalar, b: &Scalar) -> Point {
    // SAFETY: tinyssh is compiled with AVX2 (lib.rs).
    unsafe { mul_vartime_avx2(p, a, b) }
}

#[target_feature(enable = "avx2")]
fn mul_vartime_avx2(p: &Point, a: &Scalar, b: &Scalar) -> Point {
    let (a_naf, b_naf) = (naf::<5>(&a.to_bytes()), naf::<B_NAF_WIDTH>(&b.to_bytes()));
    let mut s = Scratch::new();
    // P, 3P, ..., 15P.
    let first = Point4::from_point(p);
    let mut twice = first;
    twice.double(&mut s);
    let twice = twice.cached();
    let mut table = [first.cached(); 8];
    let mut acc = first;
    for slot in table.iter_mut().skip(1) {
        acc.add::<false>(&twice, &mut s);
        *slot = acc.cached();
    }
    let digits = a_naf.iter().zip(&b_naf);
    let Some(top) = digits.clone().rposition(|(&da, &db)| da != 0 || db != 0) else {
        return Point4::IDENTITY.to_point();
    };
    let mut r = Point4::IDENTITY;
    for (i, (&da, &db)) in digits.take(top.saturating_add(1)).enumerate().rev() {
        // The top digits start from the identity, which needs no doubling.
        if i != top {
            r.double(&mut s);
        }
        r.add_digit(da, &table, &mut s);
        r.add_digit(db, b_table(), &mut s);
    }
    r.to_point()
}

/// The odd multiples of B in a width-`B_NAF_WIDTH` NAF.
const B_ENTRIES: usize = 1 << (B_NAF_WIDTH - 2);

/// `ODD_MULTIPLES_4WAY` as cached points.
fn b_table() -> &'static [Cached4; B_ENTRIES] {
    let raw: *const [[[[u64; 4]; 10]; 2]; B_ENTRIES] = &ODD_MULTIPLES_4WAY.0;
    // SAFETY: `Cached4` is `repr(C)` with two `F4`s, each `repr(transparent)`
    // over ten 32-byte vectors, so it has the layout of `[[[u64; 4]; 10]; 2]`;
    // the table is 32-byte aligned and every bit pattern is a valid vector.
    unsafe { &*raw.cast::<[Cached4; B_ENTRIES]>() }
}

impl Scratch {
    #[target_feature(enable = "avx2")]
    fn new() -> Self {
        let zero = F4([[_mm256_setzero_si256(); 2]; 5]);
        Self {
            a: zero,
            a19: zero,
            b: zero,
            c: zero,
            c19: zero,
        }
    }
}

impl Point4 {
    /// (0, 1, 1, 0).
    const IDENTITY: Self = {
        let one = [0, 1, 1, 0];
        let zero = [0u64; 4];
        // SAFETY: `[u64; 4]` and `__m256i` have the same size, and every bit
        // pattern is a valid `__m256i`.
        let [one, zero]: [__m256i; 2] = unsafe { core::mem::transmute([one, zero]) };
        Self(F4([
            [one, zero],
            [zero, zero],
            [zero, zero],
            [zero, zero],
            [zero, zero],
        ]))
    };

    #[target_feature(enable = "avx2")]
    fn from_point(p: &Point) -> Self {
        let [x, y, z, t] = [p.x, p.y, p.z, p.t].map(|c| to_limbs(&c.freeze()));
        let mut f = Self::IDENTITY.0;
        let limbs = x.iter().zip(&y).zip(&z).zip(&t);
        for (v, (((&x, &y), &z), &t)) in f.0.as_flattened_mut().iter_mut().zip(limbs) {
            *v = _mm256_set_epi64x(
                t.cast_signed(),
                z.cast_signed(),
                y.cast_signed(),
                x.cast_signed(),
            );
        }
        Self(f)
    }

    #[target_feature(enable = "avx2")]
    fn to_point(self) -> Point {
        let mut lanes = [[0u64; 4]; 10];
        for (out, &v) in lanes.iter_mut().zip(self.0.0.as_flattened()) {
            // SAFETY: `out` is 32 writable bytes.
            unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), v) };
        }
        Point {
            x: from_lanes(&lanes, 0),
            y: from_lanes(&lanes, 1),
            z: from_lanes(&lanes, 2),
            t: from_lanes(&lanes, 3),
        }
    }

    /// self = 2 self.
    #[target_feature(enable = "avx2")]
    fn double(&mut self, s: &mut Scratch) {
        let k19 = _mm256_set1_epi64x(19);
        // (X, Y, Z, X + Y) and 19 times it.
        let inputs = (self.0.0.as_flattened().iter())
            .zip(s.a.0.as_flattened_mut())
            .zip(s.a19.0.as_flattened_mut());
        for ((&v, a), a19) in inputs {
            // Hidden from the optimizer: otherwise LLVM computes the X + Y
            // lane with a `vinserti128` into a register whose other half is
            // left undefined, so whatever last wrote that register becomes an
            // input, chaining the ten limbs together (a fifth of the time).
            let v = barrier_vec(v);
            let sum = _mm256_add_epi64(
                _mm256_permute4x64_epi64::<0x00>(v),
                _mm256_permute4x64_epi64::<0x55>(v),
            );
            *a = _mm256_blend_epi32::<LANE_D>(v, sum);
            *a19 = _mm256_mul_epu32(*a, k19);
        }
        square(&mut s.b, &s.a, &s.a19); // (S1, S2, S3, S4), one carry round
        // (S8, S5, S8, S5) in a and (S9, S6, S6, S9) in c, each with one
        // carry round.
        let m26 = _mm256_set1_epi64x((1 << 26) - 1);
        let m25 = _mm256_set1_epi64x((1 << 25) - 1);
        let (mut carry_a, mut carry_c) = (_mm256_setzero_si256(), _mm256_setzero_si256());
        let limbs = (s.b.0.iter())
            .zip(&P_2_15)
            .zip(&mut s.a.0)
            .zip(&mut s.c.0)
            .zip(&mut s.c19.0);
        for ((((&[s0, s1], &[p0, p1]), [a0, a1]), [c0, c1]), [d0, d1]) in limbs {
            let (a_even, c_even) = combine(s0, p0);
            let (a_odd, c_odd) = combine(s1, p1);
            let next = _mm256_srli_epi64::<26>(a_even);
            *a0 = _mm256_add_epi64(_mm256_and_si256(a_even, m26), carry_a);
            carry_a = _mm256_srli_epi64::<25>(a_odd);
            *a1 = _mm256_add_epi64(_mm256_and_si256(a_odd, m25), next);
            let next = _mm256_srli_epi64::<26>(c_even);
            *c0 = _mm256_add_epi64(_mm256_and_si256(c_even, m26), carry_c);
            carry_c = _mm256_srli_epi64::<25>(c_odd);
            *c1 = _mm256_add_epi64(_mm256_and_si256(c_odd, m25), next);
            *d0 = _mm256_mul_epu32(*c0, k19);
            *d1 = _mm256_mul_epu32(*c1, k19);
        }
        // Limb 0 also gets limb 9's carry. 19 times limb 0 of a
        // multiplication's second operand is never read, so c19 can stay.
        let ([[a0, _], ..], [[c0, _], ..]) = (&mut s.a.0, &mut s.c.0);
        *a0 = _mm256_add_epi64(*a0, times19_vec(carry_a));
        *c0 = _mm256_add_epi64(*c0, times19_vec(carry_c));
        mul(&mut self.0, &s.a, &s.c, &s.c19);
    }

    /// self += `digit` times the table's point, for an odd digit (with
    /// `table[j]` holding 2j + 1 times it), or nothing for zero.
    #[target_feature(enable = "avx2")]
    fn add_digit(&mut self, digit: i8, table: &[Cached4], s: &mut Scratch) {
        let Some(q) = table.get(usize::from(digit.unsigned_abs() / 2)) else {
            return;
        };
        match digit.signum() {
            1 => self.add::<false>(q, s),
            -1 => self.add::<true>(q, s),
            _ => {}
        }
    }

    /// self = self + q, or self - q for `SUB`.
    #[target_feature(enable = "avx2")]
    fn add<const SUB: bool>(&mut self, q: &Cached4, s: &mut Scratch) {
        let k19 = _mm256_set1_epi64x(19);
        let inputs = (self.0.0.as_flattened().iter())
            .zip(s.a.0.as_flattened_mut())
            .zip(TWO_P.as_flattened());
        for ((&v, a), &two_p) in inputs {
            *a = diff_sum_ab::<SUB>(v, two_p);
        }
        // (A, B, C, D) of P + Q, or (B, A, -C, D) of P - Q.
        mul(&mut s.b, &s.a, &q.q, &q.q19);
        let outputs = (s.b.0.as_flattened().iter())
            .zip(TWO_P.as_flattened())
            .zip(s.a.0.as_flattened_mut())
            .zip(s.c.0.as_flattened_mut())
            .zip(s.c19.0.as_flattened_mut());
        for ((((&v, &two_p), a), c), c19) in outputs {
            let swapped = _mm256_shuffle_epi32::<0x4e>(v);
            let r = match SUB {
                false => {
                    let negated = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), v);
                    _mm256_add_epi64(
                        _mm256_blend_epi32::<{ LANE_A | LANE_C }>(v, negated),
                        swapped,
                    )
                }
                true => {
                    let negated = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), swapped);
                    _mm256_add_epi64(
                        v,
                        _mm256_blend_epi32::<{ LANE_A | LANE_D }>(swapped, negated),
                    )
                }
            }; // (E, H, F, G)
            *a = _mm256_permute4x64_epi64::<0x3c>(r); // (E, G, G, E)
            *c = _mm256_permute4x64_epi64::<0x66>(r); // (F, H, F, H)
            *c19 = _mm256_mul_epu32(*c, k19);
        }
        mul(&mut self.0, &s.a, &s.c, &s.c19);
    }

    /// The cached form of this point.
    #[target_feature(enable = "avx2")]
    fn cached(&self) -> Cached4 {
        let k = _mm256_set_epi64x(2 * 121_666, 2 * 121_665, 121_666, 121_666);
        let mut q = self.0;
        for (v, &two_p) in q.0.as_flattened_mut().iter_mut().zip(TWO_P.as_flattened()) {
            *v = _mm256_mul_epu32(diff_sum_ab::<false>(*v, two_p), k); // < 2^46
        }
        carry_round(&mut q);
        carry_round(&mut q);
        for (v, &two_p) in q.0.as_flattened_mut().iter_mut().zip(TWO_P.as_flattened()) {
            let negated = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), *v);
            *v = _mm256_blend_epi32::<LANE_C>(*v, negated);
        }
        Cached4::new(q)
    }
}

impl Cached4 {
    #[target_feature(enable = "avx2")]
    fn new(q: F4) -> Self {
        let mut q19 = q;
        times19(&mut q19, &q);
        Self { q, q19 }
    }
}

/// (X, Y, Z, T) -> (Y - X, Y + X, T, Z) for one limb, given 2p's limb, or
/// (Y + X, Y - X, T, Z) for `SUB`.
#[target_feature(enable = "avx2")]
fn diff_sum_ab<const SUB: bool>(v: __m256i, two_p: i64) -> __m256i {
    let swapped = _mm256_shuffle_epi32::<0x4e>(v); // (Y, X, T, Z)
    let sum = match SUB {
        false => {
            let negated = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), v);
            _mm256_add_epi64(_mm256_blend_epi32::<LANE_A>(v, negated), swapped)
        }
        true => {
            let negated = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), swapped);
            _mm256_add_epi64(v, _mm256_blend_epi32::<LANE_B>(swapped, negated))
        }
    };
    _mm256_blend_epi32::<{ LANE_C | LANE_D }>(sum, swapped)
}

/// One limb of (S8, S5, S8, S5) and of (S9, S6, S6, S9) from that of
/// (S1, S2, S3, S4), given `k`'s limb for a multiple k of p above each limb:
/// S5 = S1 + S2, S6 = k + S1 - S2, S8 = S6 + 2 S3 and S9 = k + S5 - S4.
/// Each output lane is a sum of broadcast inputs, so no lane crosses over.
#[target_feature(enable = "avx2")]
fn combine(s: __m256i, k: i64) -> (__m256i, __m256i) {
    let zero = _mm256_setzero_si256();
    let k = _mm256_set1_epi64x(k);
    let s1 = _mm256_permute4x64_epi64::<0x00>(s);
    let s2 = _mm256_permute4x64_epi64::<0x55>(s);
    let s3 = _mm256_permute4x64_epi64::<0xaa>(s);
    let s4 = _mm256_permute4x64_epi64::<0xff>(s);
    let minus_s2 = _mm256_sub_epi64(k, s2);
    let a = _mm256_add_epi64(
        _mm256_add_epi64(s1, _mm256_blend_epi32::<{ LANE_A | LANE_C }>(s2, minus_s2)),
        _mm256_blend_epi32::<{ LANE_A | LANE_C }>(zero, _mm256_add_epi64(s3, s3)),
    );
    let c = _mm256_add_epi64(
        _mm256_add_epi64(s1, _mm256_blend_epi32::<{ LANE_B | LANE_C }>(s2, minus_s2)),
        _mm256_blend_epi32::<{ LANE_A | LANE_D }>(zero, _mm256_sub_epi64(k, s4)),
    );
    (a, c)
}

/// One round of parallel carries over all ten limbs (inputs below 2^46).
#[target_feature(enable = "avx2")]
fn carry_round(h: &mut F4) {
    let m26 = _mm256_set1_epi64x((1 << 26) - 1);
    let m25 = _mm256_set1_epi64x((1 << 25) - 1);
    let mut carry = _mm256_setzero_si256();
    for [even, odd] in h.0.iter_mut() {
        let next = _mm256_srli_epi64::<26>(*even);
        *even = _mm256_add_epi64(_mm256_and_si256(*even, m26), carry);
        carry = _mm256_srli_epi64::<25>(*odd);
        *odd = _mm256_add_epi64(_mm256_and_si256(*odd, m25), next);
    }
    let [[limb0, _], ..] = &mut h.0;
    *limb0 = _mm256_add_epi64(*limb0, times19_vec(carry));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve25519::edwards::{BASE, mul_base};
    use crate::curve25519::field::Fe;
    use crate::tests::Rng;

    const EVEN_MAX: u64 = (1 << 26) + (1 << 17) - 1;
    const ODD_MAX: u64 = (1 << 25) + (1 << 17) - 1;

    fn lanes(f: &F4) -> [[u64; 4]; 10] {
        core::array::from_fn(|i| {
            let mut out = [0u64; 4];
            unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), f.0.as_flattened()[i]) };
            out
        })
    }

    fn f4(lanes: &[[u64; 4]; 10]) -> F4 {
        let mut f = Point4::IDENTITY.0;
        for (v, l) in f.0.as_flattened_mut().iter_mut().zip(lanes) {
            *v = unsafe { _mm256_loadu_si256(l.as_ptr().cast()) };
        }
        f
    }

    fn normalized(f: &F4) -> bool {
        lanes(f).iter().enumerate().all(|(i, l)| {
            l.iter()
                .all(|&x| x <= if i % 2 == 1 { ODD_MAX } else { EVEN_MAX })
        })
    }

    fn random_point(rng: &mut Rng) -> Point {
        let mut k = rng.bytes::<32>();
        k[31] &= 0x7f;
        let p = mul_base(&k);
        // A random Z, so that projective representations are exercised.
        let z = Fe([rng.u64(), rng.u64(), rng.u64(), rng.u64() >> 1]);
        Point {
            x: p.x.mul(&z),
            y: p.y.mul(&z),
            z: p.z.mul(&z),
            t: p.t.mul(&z),
        }
    }

    fn same(a: &Point, b: &Point) -> bool {
        a.compress() == b.compress()
    }

    #[test]
    fn matches_scalar_formulas() {
        let mut rng = Rng::new(44);
        let mut s = unsafe { Scratch::new() };
        for _ in 0..300 {
            let (p, q) = (random_point(&mut rng), random_point(&mut rng));
            unsafe {
                let (p4, q4) = (Point4::from_point(&p), Point4::from_point(&q));
                let mut d = p4;
                d.double(&mut s);
                assert!(same(&d.to_point(), &p.double()));
                assert!(normalized(&d.0));
                let mut sum = p4;
                sum.add::<false>(&q4.cached(), &mut s);
                assert!(same(&sum.to_point(), &p.add_cached(&q.cached(), false)));
                let mut diff = p4;
                diff.add::<true>(&q4.cached(), &mut s);
                assert!(same(&diff.to_point(), &p.add_cached(&q.cached(), true)));
                let mut twice = p4;
                twice.add::<false>(&p4.cached(), &mut s);
                assert!(same(&twice.to_point(), &p.double()));
                let mut zero = p4;
                zero.add::<true>(&p4.cached(), &mut s);
                assert!(same(&zero.to_point(), &Point4::IDENTITY.to_point()));
            }
        }
    }

    /// Limbs at the bounds the operations accept (maximal, zero, mixed and
    /// random) maximize every intermediate sum: the results must be
    /// normalized and equal the scalar formulas on the same values.
    #[test]
    fn extreme_limbs() {
        let mut rng = Rng::new(0xe4);
        let mut s = unsafe { Scratch::new() };
        let lambda2 = Fe([121_666 * 121_666, 0, 0, 0]);
        for trial in 0..3000usize {
            let mut v = [[0u64; 4]; 10];
            for (i, limb) in v.iter_mut().enumerate() {
                let max = if i % 2 == 1 { ODD_MAX } else { EVEN_MAX };
                for (l, x) in limb.iter_mut().enumerate() {
                    *x = match (trial + l) % 5 {
                        0 => max,
                        1 => 0,
                        2 if (i + l) % 2 == 1 => max,
                        2 => 0,
                        _ => rng.u64() % (max + 1),
                    };
                }
            }
            let p4 = Point4(f4(&v));
            let p = p4.to_point_safe();
            unsafe {
                let mut d = p4;
                d.double(&mut s);
                assert!(normalized(&d.0), "double not normalized, trial {trial}");
                let want = p.double();
                let got = d.to_point();
                for (g, w) in [
                    (got.x, want.x),
                    (got.y, want.y),
                    (got.z, want.z),
                    (got.t, want.t),
                ] {
                    assert!(g.equals(&w), "double mismatch, trial {trial}");
                }
                // The cached point of an extreme point, and the extreme point
                // added to it: lane values are lambda^2 times the scalar ones.
                let q = p4.cached();
                assert!(
                    lanes(&q.q).iter().all(|l| l.iter().all(|&x| x < 1 << 28)),
                    "cached bound, trial {trial}"
                );
                for subtract in [false, true] {
                    let mut sum = p4;
                    match subtract {
                        false => sum.add::<false>(&q, &mut s),
                        true => sum.add::<true>(&q, &mut s),
                    }
                    assert!(normalized(&sum.0), "add not normalized, trial {trial}");
                    let want = p.add_cached(&p.cached(), subtract);
                    let got = sum.to_point();
                    for (g, w) in [
                        (got.x, want.x),
                        (got.y, want.y),
                        (got.z, want.z),
                        (got.t, want.t),
                    ] {
                        assert!(g.equals(&w.mul(&lambda2)), "add mismatch, trial {trial}");
                    }
                }
            }
        }
    }

    #[test]
    fn precomputed_table_matches() {
        let mut rng = Rng::new(0xb7);
        let mut s = unsafe { Scratch::new() };
        let table = b_table();
        assert_eq!(table.len(), 1 << (B_NAF_WIDTH - 2));
        for (j, entry) in table.iter().enumerate() {
            let mut k = [0u8; 32];
            k[0] = (2 * j + 1) as u8;
            let want = mul_base(&k);
            let p = random_point(&mut rng);
            unsafe {
                let mut sum = Point4::from_point(&p);
                sum.add::<false>(entry, &mut s);
                let mut expected = Point4::from_point(&p);
                expected.add::<false>(&Point4::from_point(&want).cached(), &mut s);
                assert!(same(&sum.to_point(), &expected.to_point()), "entry {j}");
                let mut diff = Point4::from_point(&p);
                diff.add::<true>(entry, &mut s);
                let mut expected = Point4::from_point(&p);
                expected.add::<false>(&Point4::from_point(&want.neg()).cached(), &mut s);
                assert!(same(&diff.to_point(), &expected.to_point()), "entry -{j}");
                // 19 times each limb, exactly.
                for (a, b) in lanes(&entry.q).iter().zip(lanes(&entry.q19)) {
                    assert_eq!(a.map(|x| 19 * x), b);
                }
            }
        }
    }

    #[test]
    fn mul_vartime_matches_scalar() {
        let mut rng = Rng::new(0x5ca);
        for _ in 0..200 {
            let p = random_point(&mut rng);
            let a = Scalar::from_wide(&rng.bytes::<64>());
            let b = Scalar::from_wide(&rng.bytes::<64>());
            assert!(same(&mul_vartime(&p, &a, &b), &p.mul_vartime(&a, &b)));
        }
        let zero = Scalar::from_bytes_mod(&[0; 32]);
        let p = random_point(&mut rng);
        assert!(same(
            &mul_vartime(&p, &zero, &zero),
            &Point4::IDENTITY.to_point_safe()
        ));
        assert!(same(
            &mul_vartime(&BASE, &zero, &Scalar::from_bytes_mod(&[1; 32])),
            &BASE.mul_vartime(&zero, &Scalar::from_bytes_mod(&[1; 32]))
        ));
    }

    #[test]
    fn square_matches_mul() {
        let mut rng = Rng::new(5);
        for _ in 0..2000 {
            let v: [[u64; 4]; 10] = core::array::from_fn(|_| {
                core::array::from_fn(|_| rng.u64() % (3 * (1 << 26) + (1 << 17)))
            });
            let f = f4(&v);
            let mut f19 = f;
            let (mut a, mut b) = (f, f);
            unsafe {
                times19(&mut f19, &f);
                mul(&mut a, &f, &f, &f19);
                square(&mut b, &f, &f19);
                // The second carry round of `mul`.
                carry_round(&mut b);
            }
            assert_eq!(lanes(&a), lanes(&b));
        }
    }

    impl Point4 {
        fn to_point_safe(self) -> Point {
            unsafe { self.to_point() }
        }
    }

    /// `taskset -c 2 cargo test --release --lib -- --ignored --nocapture bench`
    #[test]
    #[ignore = "benchmark"]
    fn bench_edwards4() {
        use std::hint::black_box;
        let n = 200_000u32;
        let mut s = unsafe { Scratch::new() };
        let mut p = unsafe { Point4::from_point(&BASE) };
        let q = unsafe { p.cached() };
        let t = std::time::Instant::now();
        for _ in 0..n {
            unsafe { p.double(&mut s) };
            black_box(&mut p);
        }
        let double = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..n {
            unsafe { p.add::<false>(&q, &mut s) };
            black_box(&mut p);
        }
        let add = t.elapsed().as_nanos() as f64 / n as f64;
        println!("edwards4: double {double:.1} ns, add {add:.1} ns");
    }
}
