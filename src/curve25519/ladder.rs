//! The Montgomery ladder (RFC 7748, section 5), four field elements at a
//! time in AVX2 registers.
//!
//! The ladder state (x2, z2, x3, z3) is one [`F4`]: ten 256-bit vectors,
//! vector i holding limb i of the four field elements in its four 64-bit
//! lanes. Limbs use radix 2^25.5 (26, 25, 26, ... bits). Each step does three
//! 4-way multiplications with VPMULUDQ (32 x 32 -> 64 bits):
//!
//! ```text
//! M1 = (A, B, C, D) * (A, B, B, A)                   = (AA, BB, CB, DA)
//! M2 = (AA, E, T1, T2) * (BB, BB + 121666 E, T1, T2) = (x2', z2', T1^2, T2^2)
//! M3 = M2 * (1, 1, 1, x1)                            = (x2', z2', x3', z3')
//! ```
//!
//! with A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3, E = AA - BB,
//! T1 = CB + DA and T2 = CB - DA: the RFC 7748 formulas, using
//! AA + 121665 E = BB + 121666 E.
//!
//! Bounds: "normalized" limbs are < 2^26 + 2^17 (even limbs) and
//! < 2^25 + 2^17 (odd limbs); the second operand of M2 is a little looser
//! (see [`w_u_limb`]) but its limb 0 is never multiplied by 19.
//! Subtraction adds 2p limb-wise (2p's limbs exceed normalized ones), so sums
//! and differences of normalized values are < 3 * 2^26 + 2^17. For such
//! multiplication inputs 19 * g < 2^32 (VPMULUDQ reads only the low 32 bits
//! of each lane) and every 10-term product sum is < 2^62.8, so nothing
//! overflows.
//!
//! The scalar's bits only select lanes through masks: the ladder runs in
//! constant time.

use super::field::{Fe, barrier};
use core::arch::x86_64::*;

/// Four field elements in radix 2^25.5 (see the module docs), as five pairs
/// of 26-bit and 25-bit limbs.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct F4(pub(super) [[__m256i; 2]; 5]);

/// 2p in radix 2^25.5.
pub(super) const TWO_P: [[i64; 2]; 5] = [
    [0x7ff_ffda, 0x3ff_fffe],
    [0x7ff_fffe, 0x3ff_fffe],
    [0x7ff_fffe, 0x3ff_fffe],
    [0x7ff_fffe, 0x3ff_fffe],
    [0x7ff_fffe, 0x3ff_fffe],
];

/// Bit offset of each radix-2^25.5 limb, and the total width.
const LIMB_BIT: [u32; 11] = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230, 255];

/// The ladder's result, as projective x-coordinates: `x([k]P) = x2 / z2` and
/// `x([k+1]P) = x3 / z3`.
pub(crate) struct Ladder {
    pub(crate) x2: Fe,
    pub(crate) z2: Fe,
    pub(crate) x3: Fe,
    pub(crate) z3: Fe,
}

impl Drop for Ladder {
    fn drop(&mut self) {
        for fe in [&mut self.x2, &mut self.z2, &mut self.x3, &mut self.z3] {
            crate::rng::wipe(&mut fe.0);
        }
    }
}

/// Runs the ladder over the low 255 bits of `k` (little-endian) from the
/// x-coordinate `x1` (< 2^255), in constant time.
pub(crate) fn ladder(k: &[u8; 32], x1: &Fe) -> Ladder {
    // SAFETY: tinyssh is compiled with AVX2 (lib.rs).
    unsafe { run(k, x1) }
}

/// Scratch for one ladder.
struct State {
    /// (x2, z2, x3, z3), normalized.
    v: F4,
    h: F4,
    g: F4,
    g19: F4,
    m1: F4,
    w: F4,
    u: F4,
    u19: F4,
    m2: F4,
    /// (1, 1, 1, x1) and 19 times it.
    x1: F4,
    x1_19: F4,
}

impl State {
    /// Overwrites the state in place (moving it, e.g. into `drop`, would
    /// leave the original behind).
    fn wipe(&mut self) {
        let all = [
            &mut self.v,
            &mut self.h,
            &mut self.g,
            &mut self.g19,
            &mut self.m1,
            &mut self.w,
            &mut self.u,
            &mut self.u19,
            &mut self.m2,
            &mut self.x1,
            &mut self.x1_19,
        ];
        for f4 in all {
            for v in f4.0.as_flattened_mut() {
                // SAFETY: `v` is a valid, exclusive reference, and all-zero
                // bits are a valid `__m256i`.
                unsafe { core::ptr::write_volatile(v, core::mem::zeroed()) };
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[target_feature(enable = "avx2")]
fn run(k: &[u8; 32], x1: &Fe) -> Ladder {
    let zero = F4([[_mm256_setzero_si256(); 2]; 5]);
    let mut s = State {
        v: zero,
        h: zero,
        g: zero,
        g19: zero,
        m1: zero,
        w: zero,
        u: zero,
        u19: zero,
        m2: zero,
        x1: zero,
        x1_19: zero,
    };
    let x1 = to_limbs(x1);
    let init =
        s.v.0
            .as_flattened_mut()
            .iter_mut()
            .zip(s.x1.0.as_flattened_mut())
            .zip(x1);
    for (i, ((v, x), limb)) in init.enumerate() {
        let one = i64::from(i == 0);
        let limb = limb.cast_signed();
        // _mm256_set_epi64x takes lanes 3, 2, 1, 0.
        *v = _mm256_set_epi64x(one, limb, 0, one); // (1, 0, x1, 1)
        *x = _mm256_set_epi64x(limb, one, one, one); // (1, 1, 1, x1)
    }
    times19(&mut s.x1_19, &s.x1);
    let mut swap = 0u64;
    for i in (0..255).rev() {
        let byte = k.get(i / 8).copied().unwrap_or(0);
        let bit = u64::from((byte >> (i % 8)) & 1);
        let mask = barrier(0u64.wrapping_sub(swap ^ bit));
        swap = bit;
        step(&mut s, _mm256_set1_epi64x(mask.cast_signed()));
    }
    let mask = _mm256_set1_epi64x(barrier(0u64.wrapping_sub(swap)).cast_signed());
    let mut lanes = [[0u64; 4]; 10];
    for (out, &v) in lanes.iter_mut().zip(s.v.0.as_flattened()) {
        let swapped = _mm256_permute2x128_si256::<0x01>(v, v);
        let v = _mm256_xor_si256(v, _mm256_and_si256(_mm256_xor_si256(v, swapped), mask));
        // SAFETY: `out` is 32 writable bytes.
        unsafe { _mm256_storeu_si256(out.as_mut_ptr().cast(), v) };
    }
    let out = Ladder {
        x2: from_lanes(&lanes, 0),
        z2: from_lanes(&lanes, 1),
        x3: from_lanes(&lanes, 2),
        z3: from_lanes(&lanes, 3),
    };
    crate::rng::wipe(lanes.as_flattened_mut());
    s.wipe();
    _mm256_zeroall(); // do not leave secrets in vector registers
    out
}

/// One ladder step; `swap` is all ones to exchange (x2, z2) and (x3, z3)
/// first.
#[target_feature(enable = "avx2")]
fn step(s: &mut State, swap: __m256i) {
    let k19 = _mm256_set1_epi64x(19);
    let inputs = (s.v.0.as_flattened().iter())
        .zip(s.h.0.as_flattened_mut())
        .zip(s.g.0.as_flattened_mut())
        .zip(s.g19.0.as_flattened_mut())
        .zip(TWO_P.as_flattened());
    for ((((&v, h), g), g19), &two_p) in inputs {
        let swapped = _mm256_permute2x128_si256::<0x01>(v, v);
        let v = _mm256_xor_si256(v, _mm256_and_si256(_mm256_xor_si256(v, swapped), swap));
        let q = _mm256_shuffle_epi32::<0x4e>(v); // (z2, x2, z3, x3)
        let n = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), v); // 2p - v
        *h = _mm256_add_epi64(q, _mm256_blend_epi32::<0xcc>(v, n)); // (A, B, C, D)
        let hq = _mm256_shuffle_epi32::<0x4e>(*h); // (B, A, D, C)
        *g = _mm256_permute2x128_si256::<0x20>(*h, hq); // (A, B, B, A)
        *g19 = _mm256_mul_epu32(*g, k19);
    }
    mul(&mut s.m1, &s.h, &s.g, &s.g19); // (AA, BB, CB, DA)
    // W = (AA, E, T1, T2) and U = (BB, BB + 121666 E, T1, T2), with U's
    // carry round and 19 U in the same pass.
    let m26 = _mm256_set1_epi64x((1 << 26) - 1);
    let m25 = _mm256_set1_epi64x((1 << 25) - 1);
    let mut carry = _mm256_setzero_si256();
    let inputs = (s.m1.0.iter())
        .zip(&mut s.w.0)
        .zip(&mut s.u.0)
        .zip(&mut s.u19.0)
        .zip(&TWO_P);
    for ((((&[m0, m1], [w0, w1]), [u0, u1]), [u19_0, u19_1]), &[p0, p1]) in inputs {
        let next = w_u_limb::<26>(m0, p0, m26, carry, w0, u0, u19_0);
        carry = w_u_limb::<25>(m1, p1, m25, next, w1, u1, u19_1);
    }
    // u19's limb 0 misses this carry, but it is never read.
    s.u.0[0][0] = _mm256_add_epi64(s.u.0[0][0], times19_vec(carry));
    mul(&mut s.m2, &s.w, &s.u, &s.u19); // (x2', z2', T1^2, T2^2)
    mul(&mut s.v, &s.m2, &s.x1, &s.x1_19); // (x2', z2', T1^2, x1 T2^2)
}

/// `h = f^2` lane-wise, given `f19 = 19 * f`: like `mul` with each cross
/// product computed once and doubled (55 VPMULUDQ instead of 100), but with
/// one carry round, so the output is not normalized (see `ladder_sqr.py`).
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn square(h: &mut F4, f: &F4, f19: &F4) {
    // SAFETY: as in `mul`.
    unsafe {
        core::arch::asm!(
            include_str!("ladder_sqr.s"),
            h = in(reg) h.0.as_mut_ptr(),
            f = in(reg) f.0.as_ptr(),
            f19 = in(reg) f19.0.as_ptr(),
            m = in(reg) MASKS.0.as_ptr(),
            out("ymm0") _, out("ymm1") _, out("ymm2") _, out("ymm3") _, out("ymm4") _,
            out("ymm5") _, out("ymm6") _, out("ymm7") _, out("ymm8") _, out("ymm9") _,
            out("ymm10") _, out("ymm11") _, out("ymm12") _, out("ymm13") _, out("ymm14") _,
            out("ymm15") _,
            options(att_syntax, nostack, preserves_flags),
        );
    }
}

/// One limb of W = (AA, E, T1, T2) and of U = (BB, BB + 121666 E, T1, T2)
/// from limb `m` of M1 = (AA, BB, CB, DA), with `carry` added to U's limb
/// after taking its own carry (returned) above `BITS`.
///
/// U's limbs are below 2^45 before this single parallel carry round (each
/// carry is taken from a limb before the previous one is added), and below
/// 2^26 + 2^24 (even) and 2^25 + 2^20 (odd) after it.
#[target_feature(enable = "avx2")]
fn w_u_limb<const BITS: i32>(
    m: __m256i,
    two_p: i64,
    mask: __m256i,
    carry: __m256i,
    w: &mut __m256i,
    u: &mut __m256i,
    u19: &mut __m256i,
) -> __m256i {
    let keep123 = _mm256_set_epi64x(-1, -1, -1, 0);
    let a24 = _mm256_set_epi64x(0, 0, 121_666, 0);
    let x = _mm256_unpacklo_epi64(m, m); // (AA, AA, CB, CB)
    let y = _mm256_unpackhi_epi64(m, m); // (BB, BB, DA, DA)
    let n = _mm256_sub_epi64(_mm256_set1_epi64x(two_p), y);
    *w = _mm256_add_epi64(
        x,
        _mm256_and_si256(_mm256_blend_epi32::<0xcc>(y, n), keep123),
    );
    let t = _mm256_add_epi64(_mm256_blend_epi32::<0xf0>(y, *w), _mm256_mul_epu32(*w, a24));
    *u = _mm256_add_epi64(_mm256_and_si256(t, mask), carry);
    *u19 = _mm256_mul_epu32(*u, _mm256_set1_epi64x(19));
    _mm256_srli_epi64::<BITS>(t)
}

/// The 26-bit limb mask, then the 25-bit one, for `mul`.
#[repr(C, align(32))]
struct Masks([u64; 8]);

static MASKS: Masks = Masks([
    (1 << 26) - 1,
    (1 << 26) - 1,
    (1 << 26) - 1,
    (1 << 26) - 1,
    (1 << 25) - 1,
    (1 << 25) - 1,
    (1 << 25) - 1,
    (1 << 25) - 1,
]);

/// `h = f * g` lane-wise, given `g19 = 19 * g`; the output is normalized
/// (two carry rounds). Hand-allocated assembly generated by `ladder_mul.py`:
/// with intrinsics, LLVM keeps the accumulators in memory. Inlined, so that
/// calls need no `vzeroupper` and, on Windows, no saving of xmm6-xmm15.
#[target_feature(enable = "avx2")]
#[inline]
pub(super) fn mul(h: &mut F4, f: &F4, g: &F4, g19: &F4) {
    // SAFETY: reads the 320 bytes of `f`, `g`, `g19` and `MASKS` and writes
    // the 320 bytes of `h`, all 32-byte aligned; AVX2 is enabled for the
    // whole build (lib.rs).
    unsafe {
        core::arch::asm!(
            include_str!("ladder_mul.s"),
            h = in(reg) h.0.as_mut_ptr(),
            f = in(reg) f.0.as_ptr(),
            g = in(reg) g.0.as_ptr(),
            g19 = in(reg) g19.0.as_ptr(),
            m = in(reg) MASKS.0.as_ptr(),
            out("ymm0") _,
            out("ymm1") _,
            out("ymm2") _,
            out("ymm3") _,
            out("ymm4") _,
            out("ymm5") _,
            out("ymm6") _,
            out("ymm7") _,
            out("ymm8") _,
            out("ymm9") _,
            out("ymm10") _,
            out("ymm11") _,
            out("ymm12") _,
            out("ymm13") _,
            out("ymm14") _,
            out("ymm15") _,
            options(att_syntax, nostack, preserves_flags),
        );
    }
}

/// `19 * c` for lanes below 2^32, as the carries out of the top limb are
/// (shifts and adds would be turned into a 64-bit multiplication).
#[target_feature(enable = "avx2")]
pub(super) fn times19_vec(c: __m256i) -> __m256i {
    _mm256_mul_epu32(c, _mm256_set1_epi64x(19))
}

#[target_feature(enable = "avx2")]
pub(super) fn times19(out: &mut F4, g: &F4) {
    let k19 = _mm256_set1_epi64x(19);
    for (o, &x) in out.0.as_flattened_mut().iter_mut().zip(g.0.as_flattened()) {
        *o = _mm256_mul_epu32(x, k19);
    }
}

/// `x` (< 2^255) as ten exact radix-2^25.5 limbs.
pub(super) fn to_limbs(x: &Fe) -> [u64; 10] {
    let mut out = [0u64; 10];
    for (limb, pair) in out.iter_mut().zip(LIMB_BIT.windows(2)) {
        if let &[lo, hi] = pair {
            let word = usize::try_from(lo / 64).unwrap_or(0);
            let low = x.0.get(word).copied().unwrap_or(0);
            let high = x.0.get(word.wrapping_add(1)).copied().unwrap_or(0);
            let bits = ((u128::from(high) << 64) | u128::from(low)) >> (lo % 64);
            *limb = (bits as u64) & (u64::MAX >> (64u32.wrapping_sub(hi.wrapping_sub(lo))));
        }
    }
    out
}

/// Lane `n` of ten normalized radix-2^25.5 limbs as a lazily reduced field
/// element (the sum is < 2^255 + 2^251, so it fits in 256 bits).
pub(super) fn from_lanes(lanes: &[[u64; 4]; 10], n: usize) -> Fe {
    let l = |i: usize| {
        u128::from(
            lanes
                .get(i)
                .and_then(|lane| lane.get(n))
                .copied()
                .unwrap_or(0),
        )
    };
    // Limb i starts at bit 0, 26, 51, 77, 102, 128, 153, 179, 204, 230.
    let c0 = l(0).wrapping_add(l(1) << 26).wrapping_add(l(2) << 51);
    let c1 = (c0 >> 64).wrapping_add(l(3) << 13).wrapping_add(l(4) << 38);
    let c2 = (c1 >> 64)
        .wrapping_add(l(5))
        .wrapping_add(l(6) << 25)
        .wrapping_add(l(7) << 51);
    let c3 = (c2 >> 64).wrapping_add(l(8) << 12).wrapping_add(l(9) << 38);
    Fe([c0 as u64, c1 as u64, c2 as u64, c3 as u64])
}

#[cfg(test)]
mod tests {
    //! The AVX2 step with extreme limbs: limbs at the maximum the
    //! "normalized" invariant allows maximize every intermediate sum, so this
    //! checks the overflow analysis directly. Each intermediate must stay
    //! within its documented bound and the step must match the RFC 7748
    //! formulas (computed with the scalar field arithmetic).
    use super::*;
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

    fn lane_value(f: &F4, lane: usize) -> Fe {
        from_lanes(&lanes(f), lane)
    }

    fn within(f: &F4, even_max: u64, odd_max: u64) -> bool {
        lanes(f).iter().enumerate().all(|(i, l)| {
            l.iter()
                .all(|&x| x <= if i % 2 == 1 { odd_max } else { even_max })
        })
    }

    fn new_state() -> State {
        let zero = F4(unsafe { core::mem::zeroed() });
        State {
            v: zero,
            h: zero,
            g: zero,
            g19: zero,
            m1: zero,
            w: zero,
            u: zero,
            u19: zero,
            m2: zero,
            x1: zero,
            x1_19: zero,
        }
    }

    #[test]
    fn step_with_extreme_limbs() {
        let mut rng = Rng::new(0x5eed);
        let mut s = new_state();
        let loose = 3 * (1 << 26) + (1 << 17); // H, G and W bound
        for trial in 0..3000usize {
            // All maximal, all zero, alternating, or random within bounds.
            let mut v = [[0u64; 4]; 10];
            let mut x1 = [0u64; 10];
            for i in 0..10 {
                let max = if i % 2 == 1 { ODD_MAX } else { EVEN_MAX };
                let x_max = if i % 2 == 1 {
                    (1 << 25) - 1
                } else {
                    (1 << 26) - 1
                };
                x1[i] = if trial % 3 == 0 {
                    x_max
                } else {
                    rng.u64() % (x_max + 1)
                };
                for (l, slot) in v[i].iter_mut().enumerate() {
                    *slot = match (trial + l) % 5 {
                        0 => max,
                        1 => 0,
                        2 if (i + l) % 2 == 1 => max,
                        2 => 0,
                        _ => rng.u64() % (max + 1),
                    };
                }
            }
            let to_vec = |l: [u64; 4]| unsafe { _mm256_loadu_si256(l.as_ptr().cast()) };
            for i in 0..10 {
                s.v.0.as_flattened_mut()[i] = to_vec(v[i]);
                let one = u64::from(i == 0);
                s.x1.0.as_flattened_mut()[i] = to_vec([one, one, one, x1[i]]);
            }
            unsafe { times19(&mut s.x1_19, &s.x1) };
            let swap = trial % 2 == 1;
            let (x2, z2, x3, z3) = match swap {
                false => (
                    lane_value(&s.v, 0),
                    lane_value(&s.v, 1),
                    lane_value(&s.v, 2),
                    lane_value(&s.v, 3),
                ),
                true => (
                    lane_value(&s.v, 2),
                    lane_value(&s.v, 3),
                    lane_value(&s.v, 0),
                    lane_value(&s.v, 1),
                ),
            };
            let x1 = lane_value(&s.x1, 3);
            let (a, b, c, d) = (x2.add(&z2), x2.sub(&z2), x3.add(&z3), x3.sub(&z3));
            let (aa, bb, da, cb) = (a.square(), b.square(), d.mul(&a), c.mul(&b));
            let e = aa.sub(&bb);
            let want = [
                aa.mul(&bb),
                e.mul(&aa.add(&e.mul(&Fe([121_665, 0, 0, 0])))),
                da.add(&cb).square(),
                x1.mul(&da.sub(&cb).square()),
            ];
            unsafe { step(&mut s, _mm256_set1_epi64x(if swap { -1 } else { 0 })) };
            assert!(
                within(&s.h, loose, loose) && within(&s.g, loose, loose),
                "H/G bound, trial {trial}"
            );
            assert!(within(&s.w, loose, loose), "W bound, trial {trial}");
            assert!(
                within(&s.u, (1 << 26) + (1 << 24), (1 << 25) + (1 << 20)),
                "U bound, trial {trial}"
            );
            for (name, f) in [("M1", &s.m1), ("M2", &s.m2), ("M3", &s.v)] {
                assert!(
                    within(f, EVEN_MAX, ODD_MAX),
                    "{name} not normalized, trial {trial}"
                );
            }
            for (lane, want) in want.iter().enumerate() {
                assert!(
                    lane_value(&s.v, lane).equals(want),
                    "lane {lane} mismatch, trial {trial}"
                );
            }
        }
    }

    #[test]
    fn limbs_round_trip() {
        let mut rng = Rng::new(3);
        for _ in 0..1000 {
            let x = Fe([rng.u64(), rng.u64(), rng.u64(), rng.u64() >> 1]);
            let limbs = to_limbs(&x);
            assert!(
                limbs
                    .iter()
                    .enumerate()
                    .all(|(i, &l)| l < 1 << (26 - i % 2))
            );
            assert_eq!(from_lanes(&limbs.map(|l| [0, l, 0, 0]), 1).0, x.0);
        }
    }
}
