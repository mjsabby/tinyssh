//! Integers modulo L = 2^252 + 27742317777372353535851937790883648493, the
//! order of the Ed25519 base point.
//!
//! Reduction is Barrett's (Handbook of Applied Cryptography, algorithm
//! 14.42, with b = 2^64 and k = 4): a fixed sequence of multiplications and
//! two masked conditional subtractions, so it runs in constant time.

use super::field::barrier;

/// L, little-endian.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// floor(2^512 / L).
const MU: [u64; 5] = [
    0xed9c_e5a3_0a2c_131b,
    0x2106_215d_0863_29a7,
    0xffff_ffff_ffff_ffeb,
    0xffff_ffff_ffff_ffff,
    0xf,
];

/// An integer modulo L, fully reduced.
#[derive(Clone, Copy)]
pub(crate) struct Scalar([u64; 4]);

impl Scalar {
    /// A 64-byte little-endian integer (a SHA-512 digest) modulo L.
    pub(crate) fn from_wide(bytes: &[u8; 64]) -> Self {
        Self(reduce(&words(bytes)))
    }

    /// A 32-byte little-endian integer modulo L.
    pub(crate) fn from_bytes_mod(bytes: &[u8; 32]) -> Self {
        Self(reduce(&words(bytes)))
    }

    /// The scalar in `bytes` if it is below L, as RFC 8032 requires of the
    /// S half of a signature. Not constant time: S is public.
    pub(crate) fn from_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let x: [u64; 4] = words(bytes);
        for (xi, li) in x.iter().zip(&L).rev() {
            if xi != li {
                return (xi < li).then_some(Self(x));
            }
        }
        None
    }

    /// `a * b + c` modulo L.
    pub(crate) fn mul_add(a: &Self, b: &Self, c: &Self) -> Self {
        // a, b, c < L < 2^253, so the result is below 2^507.
        let mut x: [u64; 8] = mul(&a.0, &b.0);
        let mut carry = false;
        for (xi, &ci) in x.iter_mut().zip(c.0.iter().chain(&[0; 4])) {
            (*xi, carry) = xi.carrying_add(ci, carry);
        }
        let out = Self(reduce(&x));
        crate::rng::wipe(&mut x);
        out
    }

    /// The little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// Overwrites a secret scalar.
    pub(crate) fn wipe(&mut self) {
        crate::rng::wipe(&mut self.0);
    }
}

/// The little-endian 64-bit words of `bytes` (missing ones are zero).
fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut out = [0u64; N];
    // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
    }
    out
}

/// The low `N` words of `a * b`.
fn mul<const N: usize>(a: &[u64], b: &[u64]) -> [u64; N] {
    let mut out = [0u64; N];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0;
        for (o, &bj) in out.iter_mut().skip(i).zip(b) {
            (*o, carry) = ai.carrying_mul_add(bj, carry, *o);
        }
        if let Some(o) = out.get_mut(i.wrapping_add(b.len())) {
            *o = carry;
        }
    }
    out
}

/// `x` modulo L for any `x` < 2^512.
fn reduce(x: &[u64; 8]) -> [u64; 4] {
    // q3 = floor(floor(x / b^3) * MU / b^5) is at most 2 below floor(x / L).
    let [x0, x1, x2, x3, x4, x5, x6, x7] = *x;
    let mut q2: [u64; 10] = mul(&[x3, x4, x5, x6, x7], &MU);
    let [_, _, _, _, _, mut q3 @ ..] = q2;
    // r = x - q3 L, computed modulo b^5, is below 3L.
    let mut q3l: [u64; 5] = mul(&q3, &L);
    let mut r = [0u64; 5];
    let mut borrow = false;
    for ((ri, xi), qi) in r.iter_mut().zip([x0, x1, x2, x3, x4]).zip(q3l) {
        (*ri, borrow) = xi.borrowing_sub(qi, borrow);
    }
    let [r0, r1, r2, r3, _] = subtract_l_if_above(subtract_l_if_above(r));
    // The quotient says how far a secret value is from its remainder.
    for words in [&mut q2[..], &mut q3, &mut q3l, &mut r] {
        crate::rng::wipe(words);
    }
    [r0, r1, r2, r3]
}

/// `r - L` if `r >= L`, else `r`, in constant time.
fn subtract_l_if_above(r: [u64; 5]) -> [u64; 5] {
    let [l0, l1, l2, l3] = L;
    let mut d = [0u64; 5];
    let mut borrow = false;
    for ((di, ri), li) in d.iter_mut().zip(r).zip([l0, l1, l2, l3, 0]) {
        (*di, borrow) = ri.borrowing_sub(li, borrow);
    }
    // All ones if the subtraction borrowed (r < L): keep r.
    let keep = barrier(0u64.wrapping_sub(u64::from(borrow)));
    let mut out = [0u64; 5];
    for ((o, ri), di) in out.iter_mut().zip(r).zip(d) {
        *o = di ^ ((di ^ ri) & keep);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Rng;

    /// `x mod L` by shift-and-subtract long division, one bit at a time.
    fn reference(x: &[u64; 8]) -> [u64; 4] {
        let l = [L[0], L[1], L[2], L[3], 0];
        let mut r = [0u64; 5];
        for bit in (0..512).rev() {
            // r = 2 r + bit (r < L < 2^253, so this fits)
            for i in (1..5).rev() {
                r[i] = (r[i] << 1) | (r[i - 1] >> 63);
            }
            r[0] = (r[0] << 1) | ((x[bit / 64] >> (bit % 64)) & 1);
            let ge = (0..5)
                .rev()
                .find(|&i| r[i] != l[i])
                .is_none_or(|i| r[i] > l[i]);
            if ge {
                let mut borrow = false;
                for i in 0..5 {
                    (r[i], borrow) = r[i].borrowing_sub(l[i], borrow);
                }
            }
        }
        [r[0], r[1], r[2], r[3]]
    }

    fn wide_cases() -> Vec<[u64; 8]> {
        let m = u64::MAX;
        let mut cases = vec![
            [0; 8],
            [1, 0, 0, 0, 0, 0, 0, 0],
            [L[0] - 1, L[1], L[2], L[3], 0, 0, 0, 0],
            [L[0], L[1], L[2], L[3], 0, 0, 0, 0],
            [L[0] + 1, L[1], L[2], L[3], 0, 0, 0, 0],
            [m, m, m, m, 0, 0, 0, 0],
            [0, 0, 0, 0, 1, 0, 0, 0],
            [m; 8],
            [0, 0, 0, 0, 0, 0, 0, 1 << 63],
        ];
        let mut rng = Rng::new(0x4c);
        cases.extend((0..20_000).map(|_| core::array::from_fn(|_| rng.u64())));
        // Multiples of L and their neighbours stress the final subtractions.
        for k in 1..64u64 {
            let mut x: [u64; 8] = mul(&L, &[k * 0x0123_4567_89ab_cdef, k]);
            cases.push(x);
            x[0] = x[0].wrapping_sub(1);
            cases.push(x);
        }
        cases
    }

    #[test]
    fn reduction_matches_long_division() {
        for x in wide_cases() {
            assert_eq!(reduce(&x), reference(&x), "x={x:x?}");
        }
    }

    #[test]
    fn mul_add_matches_long_division() {
        let mut rng = Rng::new(0x5ca1a);
        for _ in 0..5_000 {
            let [a, b, c] = [0; 3].map(|_| Scalar::from_wide(&rng.bytes::<64>()));
            let mut x: [u64; 8] = mul(&a.0, &b.0);
            let mut carry = false;
            for (xi, ci) in x.iter_mut().zip(c.0.into_iter().chain([0; 4])) {
                (*xi, carry) = xi.carrying_add(ci, carry);
            }
            assert_eq!(Scalar::mul_add(&a, &b, &c).0, reference(&x));
        }
    }

    #[test]
    fn canonical_encodings() {
        let l = Scalar(L).to_bytes();
        assert!(Scalar::from_canonical(&l).is_none());
        assert!(Scalar::from_canonical(&[0xff; 32]).is_none());
        let mut below = l;
        below[0] -= 1;
        assert_eq!(
            Scalar::from_canonical(&below).map(|s| s.0),
            Some([L[0] - 1, L[1], L[2], L[3]])
        );
        assert_eq!(Scalar::from_canonical(&[0; 32]).map(|s| s.0), Some([0; 4]));
        let mut above = l;
        above[16] = 1; // L + 2^128
        assert!(Scalar::from_canonical(&above).is_none());
    }
}
