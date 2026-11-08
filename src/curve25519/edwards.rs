//! Points on edwards25519, -x^2 + y^2 = 1 + d x^2 y^2, for Ed25519.
//!
//! Secret scalars only meet [`mul_base`], a fixed sequence of table lookups
//! (each reading a whole table row), mixed additions and doublings. Everything
//! else is variable-time arithmetic for verifying signatures, where every
//! input is public.

use super::base_table::BASE_TABLE;
use super::field::{Fe, barrier_vec};
#[cfg(test)]
use super::scalar::Scalar;
use core::arch::x86_64::*;

/// d = -121665 / 121666.
const D: Fe = Fe([
    0x75eb_4dca_1359_78a3,
    0x0070_0a4d_4141_d8ab,
    0x8cc7_4079_7779_e898,
    0x5203_6cee_2b6f_fe73,
]);
/// 2d.
#[cfg(test)]
const D2: Fe = Fe([
    0xebd6_9b94_26b2_f159,
    0x00e0_149a_8283_b156,
    0x198e_80f2_eef3_d130,
    0x2406_d9dc_56df_fce7,
]);
/// A square root of -1.
const SQRT_M1: Fe = Fe([
    0xc4ee_1b27_4a0e_a0b0,
    0x2f43_1806_ad2f_e478,
    0x2b4d_0099_3dfb_d7a7,
    0x2b83_2480_4fc1_df0b,
]);
/// The base point B: x, y = 4/5 and xy.
#[cfg(test)]
pub(super) const BASE: Point = Point {
    x: Fe([
        0xc956_2d60_8f25_d51a,
        0x692c_c760_9525_a7b2,
        0xc0a4_e231_fdd6_dc5c,
        0x2169_36d3_cd6e_53fe,
    ]),
    y: Fe([
        0x6666_6666_6666_6658,
        0x6666_6666_6666_6666,
        0x6666_6666_6666_6666,
        0x6666_6666_6666_6666,
    ]),
    z: Fe::ONE,
    t: Fe([
        0x6dde_8ab3_a5b7_dda3,
        0x20f0_9f80_7751_52f5,
        0x66ea_4e8e_64ab_e37d,
        0x6787_5f0f_d78b_7665,
    ]),
};
/// Extended coordinates (X : Y : Z : T): x = X / Z, y = Y / Z, xy = T / Z.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) z: Fe,
    pub(super) t: Fe,
}

/// A point prepared for additions: (Y + X, Y - X, Z, 2dT).
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct Cached {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl Point {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Decodes a point (RFC 8032, section 5.1.3), rejecting non-canonical
    /// encodings. Not constant time.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let mut y = *bytes;
        let sign = y[31] >> 7;
        y[31] &= 0x7f;
        let y = Fe::from_bytes(&y);
        if y.freeze().0 != y.0 {
            return None; // y >= p
        }
        // x^2 = u / v; x = u v^3 (u v^7)^((p - 5) / 8), times sqrt(-1) if
        // that squares to -u / v instead.
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = yy.mul(&D).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v3.square().mul(&v)).pow22523());
        let vxx = v.mul(&x.square());
        if !vxx.equals(&u) {
            if !vxx.equals(&u.neg()) {
                return None; // not on the curve
            }
            x = x.mul(&SQRT_M1);
        }
        if x.equals(&Fe::ZERO) && sign == 1 {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    /// The encoding: y, with the top bit set if x is odd.
    pub(crate) fn compress(&self) -> [u8; 32] {
        let z = self.z.invert();
        let mut out = self.y.mul(&z).to_bytes();
        out[31] |= self.x.mul(&z).is_negative() << 7;
        out
    }

    pub(crate) fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Whether `[8]P` is the identity (a "weak" public key).
    pub(crate) fn is_small_order(&self) -> bool {
        let p = self.double().double().double();
        p.x.equals(&Fe::ZERO) && p.y.equals(&p.z)
    }

    /// `[a]P + [b]B`, in variable time with the scalar formulas: the
    /// reference for `edwards4`.
    #[cfg(test)]
    pub(super) fn mul_vartime(&self, a: &Scalar, b: &Scalar) -> Self {
        let (a_naf, b_naf) = (naf::<5>(&a.to_bytes()), naf::<5>(&b.to_bytes()));
        let (a_table, b_table) = (odd_multiples(self), odd_multiples(&BASE));
        let mut r = Self::IDENTITY;
        for (&da, &db) in a_naf.iter().zip(&b_naf).rev() {
            r = r.double().add_digit(da, &a_table).add_digit(db, &b_table);
        }
        r
    }

    /// 2P ("dbl-2008-hwcd" for a = -1).
    pub(super) fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let zz = self.z.square();
        let c = zz.add(&zz);
        let h = a.add(&b);
        let e = h.sub(&self.x.add(&self.y).square());
        let g = a.sub(&b);
        let f = c.add(&g);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    #[cfg(test)]
    /// P + Q ("add-2008-hwcd-3"), or P - Q.
    pub(super) fn add_cached(&self, q: &Cached, subtract: bool) -> Self {
        let (q_plus, q_minus) = match subtract {
            false => (&q.y_plus_x, &q.y_minus_x),
            true => (&q.y_minus_x, &q.y_plus_x),
        };
        let a = self.y.sub(&self.x).mul(q_minus);
        let b = self.y.add(&self.x).mul(q_plus);
        let c = self.t.mul(&q.t2d);
        let zz = self.z.mul(&q.z);
        let d = zz.add(&zz);
        let (f, g) = match subtract {
            false => (d.sub(&c), d.add(&c)),
            true => (d.add(&c), d.sub(&c)),
        };
        let (e, h) = (b.sub(&a), b.add(&a));
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    #[cfg(test)]
    /// Adds `digit` times the point whose odd multiples are in `table`.
    fn add_digit(&self, digit: i8, table: &[Cached; 8]) -> Self {
        match table.get(usize::from(digit.unsigned_abs() / 2)) {
            Some(q) if digit > 0 => self.add_cached(q, false),
            Some(q) if digit < 0 => self.add_cached(q, true),
            _ => *self,
        }
    }

    #[cfg(test)]
    pub(super) fn cached(&self) -> Cached {
        Cached {
            y_plus_x: self.y.add(&self.x),
            y_minus_x: self.y.sub(&self.x),
            z: self.z,
            t2d: self.t.mul(&D2),
        }
    }
}

#[cfg(test)]
/// P, 3P, 5P, ..., 15P.
fn odd_multiples(p: &Point) -> [Cached; 8] {
    let p2 = p.double().cached();
    let mut table = [p.cached(); 8];
    let mut acc = *p;
    for slot in table.iter_mut().skip(1) {
        acc = acc.add_cached(&p2, false);
        *slot = acc.cached();
    }
    table
}

/// The width-5 non-adjacent form of `k` < 2^255: digits are zero or odd in
/// [-15, 15], and nonzero digits are at least five positions apart.
pub(super) fn naf<const W: u32>(k: &[u8; 32]) -> [i8; 256] {
    let mut words = [0u64; 5];
    // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for (word, chunk) in words.iter_mut().zip(k.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
    }
    let width = 1u64.wrapping_shl(W);
    let mut naf = [0i8; 256];
    let mut carry = 0u64;
    let mut pos = 0usize;
    while let Some(digit) = naf.get_mut(pos) {
        let (word, bit) = (pos / 64, pos % 64);
        let low = words.get(word).copied().unwrap_or(0) >> bit;
        let high = words.get(word.wrapping_add(1)).copied().unwrap_or(0);
        let high = high
            .checked_shl(64u32.wrapping_sub(bit as u32))
            .unwrap_or(0);
        let window = carry.wrapping_add((low | high) & width.wrapping_sub(1));
        if window & 1 == 0 {
            pos = pos.wrapping_add(1);
            continue;
        }
        // An odd window becomes a digit in (-width/2, width/2); a negative
        // one carries.
        (*digit, carry) = match window < width / 2 {
            true => (window as i8, 0),
            false => (window.wrapping_sub(width) as i8, 1),
        };
        pos = pos.wrapping_add(W as usize);
    }
    naf
}

/// An affine point prepared for mixed additions: (y + x, y - x, 2dxy).
#[derive(Clone, Copy)]
struct Niels {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

impl Niels {
    const ZERO: Self = Self {
        y_plus_x: Fe::ZERO,
        y_minus_x: Fe::ZERO,
        xy2d: Fe::ZERO,
    };

    fn wipe(&mut self) {
        for fe in [&mut self.y_plus_x, &mut self.y_minus_x, &mut self.xy2d] {
            crate::rng::wipe(&mut fe.0);
        }
    }
}

impl Point {
    /// P + Q for an affine Q ("madd-2008-hwcd-3"): seven multiplications.
    #[inline]
    fn add_niels(&self, q: &Niels) -> Self {
        let a = self.y.sub(&self.x).mul(&q.y_minus_x);
        let b = self.y.add(&self.x).mul(&q.y_plus_x);
        let c = self.t.mul(&q.xy2d);
        let d = self.z.add(&self.z);
        let (e, f, g, h) = (b.sub(&a), d.sub(&c), d.add(&c), b.add(&a));
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// The Montgomery u-coordinate (1 + y) / (1 - y), encoded: what X25519
    /// computes for the same scalar.
    #[cfg(test)]
    pub(crate) fn to_montgomery(self) -> [u8; 32] {
        self.z
            .add(&self.y)
            .mul(&self.z.sub(&self.y).invert())
            .to_bytes()
    }
}

/// `[k]B` for the little-endian `k` < 2^255, in constant time.
///
/// With k = sum e_i 16^i for signed digits e_i in [-8, 8], the odd-indexed
/// digits are added first from the table rows of 256^(i/2) B, the sum is
/// multiplied by 16, and the even-indexed digits are added (as in ref10).
/// Each digit's multiple is chosen by reading the whole row.
pub(crate) fn mul_base(k: &[u8; 32]) -> Point {
    // SAFETY: tinyssh is compiled with AVX2 (lib.rs).
    unsafe { mul_base_avx2(k) }
}

#[target_feature(enable = "avx2")]
fn mul_base_avx2(k: &[u8; 32]) -> Point {
    let mut digits = radix16(k);
    // Each selected multiple reveals its digit (by comparison with the
    // table), so all of them go through this one buffer, wiped at the end.
    let mut q = Niels::ZERO;
    let mut h = Point::IDENTITY;
    for (row, &[_, odd]) in BASE_TABLE.0.iter().zip(&digits) {
        select_niels(&mut q, row, odd);
        h = h.add_niels(&q);
    }
    h = h.double().double().double().double();
    for (row, &[even, _]) in BASE_TABLE.0.iter().zip(&digits) {
        select_niels(&mut q, row, even);
        h = h.add_niels(&q);
    }
    q.wipe();
    crate::rng::wipe(digits.as_flattened_mut());
    h
}

/// The signed radix-16 digits of `k` < 2^255, as (even, odd) pairs: each in
/// [-8, 8), the last in [-8, 8].
fn radix16(k: &[u8; 32]) -> [[i8; 2]; 32] {
    let mut digits = [[0i8; 2]; 32];
    for ([low, high], byte) in digits.iter_mut().zip(k) {
        *low = (byte & 15).cast_signed();
        *high = (byte >> 4).cast_signed();
    }
    let mut carry = 0i8;
    if let Some((last, rest)) = digits.as_flattened_mut().split_last_mut() {
        for digit in rest {
            let v = digit.wrapping_add(carry);
            carry = v.wrapping_add(8) >> 4;
            *digit = v.wrapping_sub(carry << 4);
        }
        *last = last.wrapping_add(carry);
    }
    digits
}

/// `digit` times the row's point (`row[j]` holds j + 1 times it) into
/// `out`, comparing the digit with every entry's index, so that neither the
/// memory access nor the time depends on it. The masks go through barriers
/// so that the blends cannot be turned into a branch.
#[target_feature(enable = "avx2")]
fn select_niels(out: &mut Niels, row: &[[u64; 12]; 8], digit: i8) {
    let sign = digit >> 7; // 0 or -1
    let magnitude = i64::from((digit ^ sign).wrapping_sub(sign));
    let wanted = barrier_vec(_mm256_set1_epi64x(magnitude));
    let one = _mm256_set_epi64x(0, 0, 0, 1);
    let (mut plus, mut minus, mut xy2d) = (one, one, _mm256_setzero_si256()); // the identity
    for (j, entry) in (1i64..).zip(row) {
        let equal = barrier_vec(_mm256_cmpeq_epi64(wanted, _mm256_set1_epi64x(j)));
        let entry = entry.as_ptr().cast::<__m256i>();
        // SAFETY: an entry is 96 bytes: three vectors.
        let (a, b, c) = unsafe {
            (
                _mm256_loadu_si256(entry),
                _mm256_loadu_si256(entry.add(1)),
                _mm256_loadu_si256(entry.add(2)),
            )
        };
        plus = _mm256_blendv_epi8(plus, a, equal);
        minus = _mm256_blendv_epi8(minus, b, equal);
        xy2d = _mm256_blendv_epi8(xy2d, c, equal);
    }
    // -Q = (y - x, y + x, -2dxy): swap the first two coordinates and negate
    // the third, under a mask. The negation is 2p - xy2d limb by limb: every
    // table entry has a low limb of at most 2^64 - 38, that of 2p (checked
    // by base_table.py), so no limb borrows.
    let swap = barrier_vec(_mm256_set1_epi64x(i64::from(sign)));
    let two_p = _mm256_set_epi64x(-1, -1, -1, -38);
    let negated = _mm256_sub_epi64(two_p, xy2d);
    let store = |fe: &mut Fe, v| {
        // SAFETY: `fe` is 32 bytes.
        unsafe { _mm256_storeu_si256(fe.0.as_mut_ptr().cast(), v) }
    };
    store(&mut out.y_plus_x, _mm256_blendv_epi8(plus, minus, swap));
    store(&mut out.y_minus_x, _mm256_blendv_epi8(minus, plus, swap));
    store(&mut out.xy2d, _mm256_blendv_epi8(xy2d, negated, swap));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Rng;

    const IDENTITY_BYTES: [u8; 32] = {
        let mut out = [0; 32];
        out[0] = 1;
        out
    };
    const NEG_BASE_BYTES: [u8; 32] = {
        let mut out = [0x66; 32];
        out[0] = 0x58;
        out[31] = 0xe6;
        out
    };
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    fn le_add(a: &[u8; 32], k: i64) -> [u8; 32] {
        let mut out = *a;
        let mut carry = k as i128;
        for b in out.iter_mut() {
            let v = *b as i128 + carry;
            *b = v.rem_euclid(256) as u8;
            carry = v.div_euclid(256);
        }
        out
    }

    /// `[k]B` from the table against the variable-time w-NAF arithmetic,
    /// including k = 0 and k = -1 (mod L).
    /// `select_niels` negates xy2d limb by limb, without borrows.
    #[test]
    fn table_entries_negate_without_borrows() {
        for entry in BASE_TABLE.0.as_flattened() {
            assert!(entry[8] <= u64::MAX - 37);
        }
    }

    #[test]
    fn mul_base_matches_edwards_arithmetic() {
        let mut rng = Rng::new(0xb45e);
        let mut ks = vec![
            [0u8; 32],
            le_add(&[0; 32], 1),
            le_add(&[0; 32], 2),
            le_add(&L_BYTES, -1),
            L_BYTES,
        ];
        ks.push(le_add(&L_BYTES, 1));
        ks.extend((0..300).map(|_| {
            let mut k = rng.bytes::<32>();
            k[31] &= 0x7f;
            k
        }));
        for k in ks {
            let want = BASE.mul_vartime(
                &Scalar::from_bytes_mod(&[0; 32]),
                &Scalar::from_bytes_mod(&k),
            );
            assert_eq!(mul_base(&k).compress(), want.compress(), "k={k:02x?}");
        }
        assert_eq!(mul_base(&[0; 32]).compress(), IDENTITY_BYTES);
        assert_eq!(mul_base(&le_add(&L_BYTES, -1)).compress(), NEG_BASE_BYTES);
        assert_eq!(BASE.neg().compress(), NEG_BASE_BYTES);
    }

    #[test]
    #[ignore = "benchmark"]
    fn bench_edwards() {
        use std::hint::black_box;
        let n = 200_000u32;
        let mut p = BASE;
        let t = std::time::Instant::now();
        for _ in 0..n {
            p = black_box(p).double();
        }
        let dbl = t.elapsed().as_nanos() as f64 / n as f64;
        let q = BASE.double().cached();
        let t = std::time::Instant::now();
        for _ in 0..n {
            p = black_box(p).add_cached(&q, false);
        }
        let add = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..1000 {
            p = black_box(p).mul_vartime(
                &Scalar::from_wide(&[0x5a; 64]),
                &Scalar::from_wide(&[0xa5; 64]),
            );
        }
        let mv = t.elapsed().as_nanos() as f64 / 1000.0;
        let t = std::time::Instant::now();
        for i in 0..10_000u32 {
            let mut k = [0x5a; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            p = black_box(mul_base(black_box(&k)));
        }
        let mb = t.elapsed().as_nanos() as f64 / 10_000.0;
        println!(
            "edwards: double {dbl:.1} ns, add {add:.1} ns, mul_vartime {mv:.0} ns, mul_base {mb:.0} ns {}",
            p.compress()[0]
        );
    }

    #[test]
    fn decompression() {
        let mut rng = Rng::new(0xdec0);
        for _ in 0..200 {
            let mut k = rng.bytes::<32>();
            k[31] &= 0x7f;
            let encoded = mul_base(&k).compress();
            let point = Point::decompress(&encoded).expect("valid point");
            assert_eq!(point.compress(), encoded);
            assert!(!point.is_small_order());
        }
        let p = super::super::field::tests::P;
        let p_bytes: [u8; 32] = core::array::from_fn(|i| (p[i / 8] >> (8 * (i % 8))) as u8);
        // y = p and y = p + 1 are non-canonical encodings of 0 and 1.
        assert!(Point::decompress(&p_bytes).is_none());
        assert!(Point::decompress(&le_add(&p_bytes, 1)).is_none());
        // x = 0 with the sign bit set.
        let mut negative_zero = IDENTITY_BYTES;
        negative_zero[31] |= 0x80;
        assert!(Point::decompress(&negative_zero).is_none());
        // y = 2 is not on the curve.
        assert!(Point::decompress(&le_add(&[0; 32], 2)).is_none());
        // The identity, (0, -1) of order 2 and (sqrt(-1), 0) of order 4
        // decode, and are flagged as small order.
        let order_four = Point {
            x: SQRT_M1,
            y: Fe::ZERO,
            z: Fe::ONE,
            t: Fe::ZERO,
        };
        for small in [IDENTITY_BYTES, le_add(&p_bytes, -1), order_four.compress()] {
            assert!(
                Point::decompress(&small)
                    .expect("on the curve")
                    .is_small_order()
            );
        }
    }

    fn check_naf<const W: u32>(k: &[u8; 32]) {
        let digits = naf::<W>(k);
        let half = 1i128 << (W - 1);
        let mut words = [0i128; 5];
        for (i, &d) in digits.iter().enumerate() {
            assert!(
                d == 0 || (d % 2 != 0 && (d as i128).abs() < half),
                "digit {d}"
            );
            words[i / 64] += (d as i128) << (i % 64);
        }
        let mut carry = 0i128;
        let mut value = [0u64; 5];
        for (v, w) in value.iter_mut().zip(words) {
            let sum = w + carry;
            *v = sum as u64;
            carry = sum >> 64;
        }
        let want: [u64; 4] =
            core::array::from_fn(|i| u64::from_le_bytes(k[8 * i..][..8].try_into().unwrap()));
        assert_eq!(
            (&value[..4], value[4], carry),
            (&want[..], 0, 0),
            "k={k:02x?}"
        );
        let span = W as usize;
        assert!(
            digits
                .windows(span)
                .all(|w| w.iter().filter(|&&d| d != 0).count() <= 1)
        );
    }

    #[test]
    fn naf_digits_reconstruct_the_scalar_widths() {
        let mut rng = Rng::new(0x1af);
        for i in 0..2000 {
            let mut k = rng.bytes::<32>();
            k[31] &= 0x7f;
            if i % 3 == 0 {
                k[31] |= 0x7f; // just below 2^255
                k[30] = 0xff;
            }
            check_naf::<5>(&k);
            check_naf::<8>(&k);
        }
    }

    #[test]
    fn naf_digits_reconstruct_the_scalar() {
        let mut rng = Rng::new(0x1af);
        for _ in 0..1000 {
            let mut k = rng.bytes::<32>();
            k[31] &= 0x7f;
            let digits = naf::<5>(&k);
            let mut words = [0i128; 5];
            for (i, &d) in digits.iter().enumerate() {
                assert!(
                    d == 0 || (d % 2 != 0 && (-15..=15).contains(&d)),
                    "digit {d}"
                );
                words[i / 64] += (d as i128) << (i % 64);
            }
            let mut carry = 0i128;
            let mut value = [0u64; 5];
            for (v, w) in value.iter_mut().zip(words) {
                let sum = w + carry;
                *v = sum as u64;
                carry = sum >> 64;
            }
            let want: [u64; 4] =
                core::array::from_fn(|i| u64::from_le_bytes(k[8 * i..][..8].try_into().unwrap()));
            assert_eq!((&value[..4], value[4], carry), (&want[..], 0, 0));
            assert!(
                digits
                    .windows(5)
                    .all(|w| w.iter().filter(|&&d| d != 0).count() <= 1)
            );
        }
    }
}
