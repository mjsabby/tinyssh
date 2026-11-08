//! Arithmetic modulo p = 2^255 - 19.
//!
//! An element is four 64-bit limbs holding any value in [0, 2^256) congruent
//! to it ("lazily reduced"): every operation accepts any such value and
//! returns one, folding with 2^256 = 38 (mod p). Only [`Fe::freeze`] produces
//! the canonical representative in [0, p).
//!
//! Multiplication, squaring, addition, subtraction and freezing are inline
//! assembly with MULX, ADCX and ADOX: compilers do not emit two interleaved
//! carry chains, and in assembly a mask or CMOV cannot be turned into a
//! secret-dependent branch. Everything here runs in constant time.

use core::arch::asm;
use core::arch::x86_64::__m256i;

/// An element of GF(2^255 - 19), lazily reduced (see the module docs).
#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 4]);

/// Reduces the 512-bit value in r8..r15 (little-endian) to 256 bits in
/// r8..r11: r[0..4] += 38 * r[4..8], then the top word, then the final carry
/// (which cannot carry again). Uses rax, rcx and rdx.
macro_rules! reduce {
    () => {
        concat!(
            "movl $38, %edx\n",
            "xorl %ecx, %ecx\n", // rcx = 0, CF = OF = 0
            "mulxq %r12, %rax, %r12\n",
            "adcxq %rax, %r8\n",
            "adoxq %r12, %r9\n",
            "mulxq %r13, %rax, %r13\n",
            "adcxq %rax, %r9\n",
            "adoxq %r13, %r10\n",
            "mulxq %r14, %rax, %r14\n",
            "adcxq %rax, %r10\n",
            "adoxq %r14, %r11\n",
            "mulxq %r15, %rax, %r15\n",
            "adcxq %rax, %r11\n",
            "adoxq %rcx, %r15\n",
            "adcxq %rcx, %r15\n", // top word <= 38
            "imulq $38, %r15, %r15\n",
            "addq %r15, %r8\n",
            "adcq %rcx, %r9\n",
            "adcq %rcx, %r10\n",
            "adcq %rcx, %r11\n",
            "cmovcq %rdx, %rcx\n", // rcx = carry ? 38 : 0
            "addq %rcx, %r8\n",
        )
    };
}

/// One row of the schoolbook product: acc[i..i+5] += a_i * b, with the low
/// halves on the CF chain (ADCX) and the high halves on the OF chain (ADOX).
macro_rules! mul_row {
    ($offset:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal, $r4:literal) => {
        concat!(
            "movq ",
            $offset,
            "({a}), %rdx\n",
            "xorl %",
            $r4,
            "d, %",
            $r4,
            "d\n",
            "mulxq 0({b}), %rax, %rcx\n",
            "adcxq %rax, %",
            $r0,
            "\n",
            "adoxq %rcx, %",
            $r1,
            "\n",
            "mulxq 8({b}), %rax, %rcx\n",
            "adcxq %rax, %",
            $r1,
            "\n",
            "adoxq %rcx, %",
            $r2,
            "\n",
            "mulxq 16({b}), %rax, %rcx\n",
            "adcxq %rax, %",
            $r2,
            "\n",
            "adoxq %rcx, %",
            $r3,
            "\n",
            "mulxq 24({b}), %rax, %rcx\n",
            "adcxq %rax, %",
            $r3,
            "\n",
            "adoxq %rcx, %",
            $r4,
            "\n",
            "adcq $0, %",
            $r4,
            "\n",
        )
    };
}

impl Fe {
    pub(crate) const ZERO: Self = Self([0; 4]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0]);

    /// The little-endian integer in `bytes`, all 256 bits of it.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            *limb = u64::from_le_bytes(chunk.try_into().unwrap_or_default());
        }
        Self(limbs)
    }

    /// The canonical little-endian encoding.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.freeze().0) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// `self * b`.
    pub(crate) fn mul(&self, b: &Self) -> Self {
        let (r0, r1, r2, r3);
        // SAFETY: reads the 32 bytes behind each pointer; MULX (BMI2) and
        // ADCX/ADOX (ADX) are enabled for the whole build (lib.rs).
        unsafe {
            asm!(
                "movq 0({a}), %rdx",
                "mulxq 0({b}), %r8, %r9",
                "mulxq 8({b}), %rax, %r10",
                "addq %rax, %r9",
                "mulxq 16({b}), %rax, %r11",
                "adcq %rax, %r10",
                "mulxq 24({b}), %rax, %r12",
                "adcq %rax, %r11",
                "adcq $0, %r12",
                mul_row!("8", "r9", "r10", "r11", "r12", "r13"),
                mul_row!("16", "r10", "r11", "r12", "r13", "r14"),
                mul_row!("24", "r11", "r12", "r13", "r14", "r15"),
                reduce!(),
                a = in(reg) self.0.as_ptr(),
                b = in(reg) b.0.as_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(att_syntax, pure, readonly, nostack),
            );
        }
        Self([r0, r1, r2, r3])
    }

    /// `self^2`: six cross products, doubled on the CF chain while the four
    /// squares are added on the OF chain (10 MULX instead of 16).
    pub(crate) fn square(&self) -> Self {
        let (r0, r1, r2, r3);
        // SAFETY: as in `mul`.
        unsafe {
            asm!(
                "movq 0({a}), %rdx",
                "mulxq 8({a}), %r9, %r10",   // a0*a1
                "mulxq 16({a}), %rax, %r11", // a0*a2
                "addq %rax, %r10",
                "mulxq 24({a}), %rax, %r12", // a0*a3
                "adcq %rax, %r11",
                "adcq $0, %r12",
                "movq 8({a}), %rdx",
                "xorl %r13d, %r13d",
                "mulxq 16({a}), %rax, %rcx", // a1*a2
                "adcxq %rax, %r11",
                "adoxq %rcx, %r12",
                "mulxq 24({a}), %rax, %rcx", // a1*a3
                "adcxq %rax, %r12",
                "adoxq %rcx, %r13",
                "adcq $0, %r13",
                "movq 16({a}), %rdx",
                "mulxq 24({a}), %rax, %r14", // a2*a3
                "addq %rax, %r13",
                "adcq $0, %r14",
                "movq 0({a}), %rdx",
                "xorl %r15d, %r15d",
                "mulxq %rdx, %r8, %rax", // a0^2
                "adcxq %r9, %r9",
                "adoxq %rax, %r9",
                "movq 8({a}), %rdx",
                "mulxq %rdx, %rax, %rcx", // a1^2
                "adcxq %r10, %r10",
                "adoxq %rax, %r10",
                "adcxq %r11, %r11",
                "adoxq %rcx, %r11",
                "movq 16({a}), %rdx",
                "mulxq %rdx, %rax, %rcx", // a2^2
                "adcxq %r12, %r12",
                "adoxq %rax, %r12",
                "adcxq %r13, %r13",
                "adoxq %rcx, %r13",
                "movq 24({a}), %rdx",
                "mulxq %rdx, %rax, %rcx", // a3^2
                "adcxq %r14, %r14",
                "adoxq %rax, %r14",
                "adcxq %r15, %r15",
                "adoxq %rcx, %r15",
                reduce!(),
                a = in(reg) self.0.as_ptr(),
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r8") r0,
                out("r9") r1,
                out("r10") r2,
                out("r11") r3,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                options(att_syntax, pure, readonly, nostack),
            );
        }
        Self([r0, r1, r2, r3])
    }

    /// `self^(2^n)`: `n` squarings with the limbs kept in registers, as
    /// in [`square`](Self::square) but with a0..a3 in r8, rsi, rdi and r15
    /// (each read for the last time before it is overwritten) and the loop
    /// counter in xmm0, every general register being taken.
    pub(crate) fn square_n(&self, n: u32) -> Self {
        if n == 0 {
            return *self;
        }
        let [a0, a1, a2, a3] = self.0;
        let (r0, r1, r2, r3);
        // SAFETY: registers only; `n` >= 1, so the loop ends.
        unsafe {
            asm!(
                "vmovq %rcx, %xmm0",
                "2:",
                "movq %r9, %rsi",
                "movq %r10, %rdi",
                "movq %r11, %r15",
                "movq %r8, %rdx",
                "mulxq %rsi, %r9, %r10",  // a0*a1
                "mulxq %rdi, %rax, %r11", // a0*a2
                "addq %rax, %r10",
                "mulxq %r15, %rax, %r12", // a0*a3
                "adcq %rax, %r11",
                "adcq $0, %r12",
                "movq %rsi, %rdx",
                "xorl %r13d, %r13d",
                "mulxq %rdi, %rax, %rcx", // a1*a2
                "adcxq %rax, %r11",
                "adoxq %rcx, %r12",
                "mulxq %r15, %rax, %rcx", // a1*a3
                "adcxq %rax, %r12",
                "adoxq %rcx, %r13",
                "adcq $0, %r13",
                "movq %rdi, %rdx",
                "mulxq %r15, %rax, %r14", // a2*a3
                "addq %rax, %r13",
                "adcq $0, %r14",
                "movq %r8, %rdx",
                "xorl %eax, %eax", // CF = OF = 0
                "mulxq %rdx, %r8, %rax", // a0^2
                "adcxq %r9, %r9",
                "adoxq %rax, %r9",
                "movq %rsi, %rdx",
                "mulxq %rdx, %rax, %rcx", // a1^2
                "adcxq %r10, %r10",
                "adoxq %rax, %r10",
                "adcxq %r11, %r11",
                "adoxq %rcx, %r11",
                "movq %rdi, %rdx",
                "mulxq %rdx, %rax, %rcx", // a2^2
                "adcxq %r12, %r12",
                "adoxq %rax, %r12",
                "adcxq %r13, %r13",
                "adoxq %rcx, %r13",
                "movq %r15, %rdx",
                "movl $0, %r15d", // keeps the flags
                "mulxq %rdx, %rax, %rcx", // a3^2
                "adcxq %r14, %r14",
                "adoxq %rax, %r14",
                "adcxq %r15, %r15",
                "adoxq %rcx, %r15",
                reduce!(),
                "vmovq %xmm0, %rcx",
                "decq %rcx",
                "vmovq %rcx, %xmm0",
                "jnz 2b",
                inout("rcx") u64::from(n) => _,
                inout("r8") a0 => r0,
                inout("r9") a1 => r1,
                inout("r10") a2 => r2,
                inout("r11") a3 => r3,
                out("rax") _,
                out("rdx") _,
                out("rsi") _,
                out("rdi") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
                out("xmm0") _,
                options(att_syntax, pure, nomem, nostack),
            );
        }
        Self([r0, r1, r2, r3])
    }

    /// `self + b`.
    pub(crate) fn add(&self, b: &Self) -> Self {
        let (t0, t1, t2, t3);
        // SAFETY: reads the 32 bytes behind each pointer.
        unsafe {
            asm!(
                "xorl {c:e}, {c:e}",
                "movq 0({a}), {t0}",
                "addq 0({b}), {t0}",
                "movq 8({a}), {t1}",
                "adcq 8({b}), {t1}",
                "movq 16({a}), {t2}",
                "adcq 16({b}), {t2}",
                "movq 24({a}), {t3}",
                "adcq 24({b}), {t3}",
                "sbbq {c}, {c}",
                "andl $38, {c:e}", // c = carry ? 38 : 0
                "addq {c}, {t0}",
                "adcq $0, {t1}",
                "adcq $0, {t2}",
                "adcq $0, {t3}",
                "sbbq {c}, {c}",
                "andl $38, {c:e}",
                "addq {c}, {t0}", // cannot carry
                a = in(reg) self.0.as_ptr(),
                b = in(reg) b.0.as_ptr(),
                t0 = out(reg) t0,
                t1 = out(reg) t1,
                t2 = out(reg) t2,
                t3 = out(reg) t3,
                c = out(reg) _,
                options(att_syntax, pure, readonly, nostack),
            );
        }
        Self([t0, t1, t2, t3])
    }

    /// `self - b`.
    pub(crate) fn sub(&self, b: &Self) -> Self {
        let (t0, t1, t2, t3);
        // SAFETY: reads the 32 bytes behind each pointer.
        unsafe {
            asm!(
                "xorl {c:e}, {c:e}",
                "movq 0({a}), {t0}",
                "subq 0({b}), {t0}",
                "movq 8({a}), {t1}",
                "sbbq 8({b}), {t1}",
                "movq 16({a}), {t2}",
                "sbbq 16({b}), {t2}",
                "movq 24({a}), {t3}",
                "sbbq 24({b}), {t3}",
                "sbbq {c}, {c}",
                "andl $38, {c:e}", // c = borrow ? 38 : 0
                "subq {c}, {t0}",
                "sbbq $0, {t1}",
                "sbbq $0, {t2}",
                "sbbq $0, {t3}",
                "sbbq {c}, {c}",
                "andl $38, {c:e}",
                "subq {c}, {t0}", // cannot borrow
                a = in(reg) self.0.as_ptr(),
                b = in(reg) b.0.as_ptr(),
                t0 = out(reg) t0,
                t1 = out(reg) t1,
                t2 = out(reg) t2,
                t3 = out(reg) t3,
                c = out(reg) _,
                options(att_syntax, pure, readonly, nostack),
            );
        }
        Self([t0, t1, t2, t3])
    }

    /// `-self`.
    pub(crate) fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// The canonical representative, in [0, p).
    pub(crate) fn freeze(&self) -> Self {
        let (t0, t1, t2, t3);
        // SAFETY: reads the 32 bytes behind the pointer.
        unsafe {
            asm!(
                "movq 0({a}), {t0}",
                "movq 8({a}), {t1}",
                "movq 16({a}), {t2}",
                "movq 24({a}), {t3}",
                // Fold bit 255 (2^255 = 19): t < 2^255 + 19 afterwards.
                "movq {t3}, {c}",
                "shrq $63, {c}",
                "btrq $63, {t3}",
                "imulq $19, {c}, {c}",
                "addq {c}, {t0}",
                "adcq $0, {t1}",
                "adcq $0, {t2}",
                "adcq $0, {t3}",
                // y = t + 19 - 2^255 = t - p; use it iff bit 255 of t + 19 is set.
                "movq {t0}, {y0}",
                "addq $19, {y0}",
                "movq {t1}, {y1}",
                "adcq $0, {y1}",
                "movq {t2}, {y2}",
                "adcq $0, {y2}",
                "movq {t3}, {y3}",
                "adcq $0, {y3}",
                "btrq $63, {y3}",
                "cmovcq {y0}, {t0}",
                "cmovcq {y1}, {t1}",
                "cmovcq {y2}, {t2}",
                "cmovcq {y3}, {t3}",
                a = in(reg) self.0.as_ptr(),
                t0 = out(reg) t0,
                t1 = out(reg) t1,
                t2 = out(reg) t2,
                t3 = out(reg) t3,
                y0 = out(reg) _,
                y1 = out(reg) _,
                y2 = out(reg) _,
                y3 = out(reg) _,
                c = out(reg) _,
                options(att_syntax, pure, readonly, nostack),
            );
        }
        Self([t0, t1, t2, t3])
    }

    /// `(self^(2^250 - 1), self^11)`, shared by [`Fe::invert`] and
    /// [`Fe::pow22523`].
    fn pow2_250_1(&self) -> (Self, Self) {
        let z2 = self.square();
        let z9 = self.mul(&z2.square_n(2));
        let z11 = z2.mul(&z9);
        let t = z9.mul(&z11.square()); // z^(2^5 - 1)
        let t = t.square_n(5).mul(&t); // z^(2^10 - 1)
        let t10 = t;
        let t = t.square_n(10).mul(&t); // z^(2^20 - 1)
        let t = t.square_n(20).mul(&t); // z^(2^40 - 1)
        let t = t.square_n(10).mul(&t10); // z^(2^50 - 1)
        let t50 = t;
        let t = t.square_n(50).mul(&t); // z^(2^100 - 1)
        let t = t.square_n(100).mul(&t); // z^(2^200 - 1)
        let t = t.square_n(50).mul(&t50); // z^(2^250 - 1)
        (t, z11)
    }

    /// `self^(p - 2)`: the inverse, or 0 for 0.
    pub(crate) fn invert(&self) -> Self {
        let (t, z11) = self.pow2_250_1();
        t.square_n(5).mul(&z11) // z^(2^255 - 21)
    }

    /// `self^((p - 5) / 8)`, for square roots.
    pub(crate) fn pow22523(&self) -> Self {
        let (t, _) = self.pow2_250_1();
        t.square_n(2).mul(self) // z^(2^252 - 3)
    }

    /// Whether the canonical representative is odd (the "sign" of
    /// RFC 8032), as 0 or 1.
    pub(crate) fn is_negative(&self) -> u8 {
        let [low, ..] = self.freeze().0;
        u8::from(low & 1 == 1)
    }

    /// Whether `self` and `b` are congruent mod p. Not constant time: only
    /// for public values.
    pub(crate) fn equals(&self, b: &Self) -> bool {
        self.freeze().0 == b.freeze().0
    }
}

/// Hides `x` from the optimizer, so that code using it as a mask cannot be
/// turned into a branch.
pub(crate) fn barrier(mut x: u64) -> u64 {
    // SAFETY: an empty assembly block that only claims to modify `x`.
    unsafe { asm!("/* {0} */", inout(reg) x, options(pure, nomem, nostack, preserves_flags)) };
    x
}

/// [`barrier`] for a vector.
#[target_feature(enable = "avx2")]
pub(crate) fn barrier_vec(mut v: __m256i) -> __m256i {
    // SAFETY: an empty assembly block that only claims to modify `v`.
    unsafe { asm!("/* {0} */", inout(ymm_reg) v, options(pure, nomem, nostack, preserves_flags)) };
    v
}

#[cfg(test)]
pub(crate) mod tests {
    //! The field arithmetic against a simple big-integer reference, including
    //! carry edge cases that random inputs essentially never reach.
    use super::Fe;
    use crate::tests::Rng;

    type U = u128;
    pub(crate) const P: [u64; 4] = [0xffff_ffff_ffff_ffed, u64::MAX, u64::MAX, u64::MAX >> 1];

    /// `x mod p` for an 8-limb `x`: fold 2^255 = 19 until the value fits,
    /// then subtract p while it is at least p.
    pub(crate) fn reference_mod(x: [u64; 8]) -> [u64; 4] {
        let mut x = x.to_vec();
        x.push(0);
        for _ in 0..4 {
            let hi: Vec<u64> = (0..5).map(|i| (x[i + 3] >> 63) | (x[i + 4] << 1)).collect();
            let lo = [x[0], x[1], x[2], x[3] & (u64::MAX >> 1)];
            let mut c: U = 0;
            for (i, xi) in x.iter_mut().enumerate() {
                c += if i < 4 { lo[i] as U } else { 0 };
                c += if i < 5 { hi[i] as U * 19 } else { 0 };
                *xi = c as u64;
                c >>= 64;
            }
        }
        for _ in 0..2 {
            let ge = x[4] != 0
                || (0..4)
                    .rev()
                    .find(|&i| x[i] != P[i])
                    .is_none_or(|i| x[i] > P[i]);
            if ge {
                let mut borrow = 0;
                for (i, xi) in x.iter_mut().enumerate().take(5) {
                    let d = (*xi as U)
                        .wrapping_sub(if i < 4 { P[i] as U } else { 0 })
                        .wrapping_sub(borrow);
                    *xi = d as u64;
                    borrow = (d >> 64) & 1;
                }
            }
        }
        [x[0], x[1], x[2], x[3]]
    }

    pub(crate) fn reference_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let mut r = [0u64; 8];
        for i in 0..4 {
            let mut c: U = 0;
            for j in 0..4 {
                c += a[i] as U * b[j] as U + r[i + j] as U;
                r[i + j] = c as u64;
                c >>= 64;
            }
            r[i + 4] = c as u64;
        }
        reference_mod(r)
    }

    /// `a + b`, or `a - b + 4p` (4p > 2^256 > b keeps it positive).
    fn reference_add(a: &[u64; 4], b: &[u64; 4], sub: bool) -> [u64; 4] {
        let p4 = [0xffff_ffff_ffff_ffb4, u64::MAX, u64::MAX, u64::MAX, 1];
        let mut r = [0u64; 8];
        let mut c: U = 0;
        let mut borrow: U = 0;
        for i in 0..5 {
            let (ai, bi) = if i < 4 {
                (a[i] as U, b[i] as U)
            } else {
                (0, 0)
            };
            if sub {
                let t = p4[i] as U + ai + c;
                c = t >> 64;
                let d = (t as u64 as U).wrapping_sub(bi).wrapping_sub(borrow);
                r[i] = d as u64;
                borrow = (d >> 64) & 1;
            } else {
                c += ai + bi;
                r[i] = c as u64;
                c >>= 64;
            }
        }
        reference_mod(r)
    }

    fn reduced(x: &[u64; 4]) -> [u64; 4] {
        reference_mod([x[0], x[1], x[2], x[3], 0, 0, 0, 0])
    }

    fn check(a: &Fe, b: &Fe) {
        let (x, y) = (&a.0, &b.0);
        let ctx = format!("a={x:x?} b={y:x?}");
        assert_eq!(a.mul(b).freeze().0, reference_mul(x, y), "mul {ctx}");
        assert_eq!(a.square().freeze().0, reference_mul(x, x), "square {ctx}");
        assert_eq!(a.add(b).freeze().0, reference_add(x, y, false), "add {ctx}");
        assert_eq!(a.sub(b).freeze().0, reference_add(x, y, true), "sub {ctx}");
        assert_eq!(
            a.neg().freeze().0,
            reference_add(&[0; 4], x, true),
            "neg {ctx}"
        );
        assert_eq!(a.freeze().0, reduced(x), "freeze {ctx}");
        assert_eq!(
            a.is_negative(),
            (reduced(x)[0] & 1) as u8,
            "is_negative {ctx}"
        );
        assert_eq!(a.equals(b), reduced(x) == reduced(y), "equals {ctx}");
    }

    /// Values around p, 2p, 2^255 and 2^256, and limb patterns that maximize
    /// carries.
    fn specials() -> Vec<Fe> {
        const M: u64 = u64::MAX;
        const H: u64 = M >> 1;
        const T: u64 = 1 << 63;
        let mut v: Vec<Fe> = [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            [19, 0, 0, 0],
            [38, 0, 0, 0],
            [M, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 0, 1],
            [M - 20, M, M, H], // p - 2
            [M - 19, M, M, H], // p - 1
            [M - 18, M, M, H], // p
            [M - 17, M, M, H], // p + 1
            [M, M, M, H],      // 2^255 - 1
            [0, 0, 0, T],      // 2^255
            [1, 0, 0, T],
            [18, 0, 0, T],
            [M - 37, M, M, M], // 2p
            [M - 18, M, M, M], // 2^256 - 19
            [M - 1, M, M, M],
            [M, M, M, M],
            [M, 0, M, 0],
            [0, M, 0, M],
            [M, M, 0, 0],
            [0, 0, M, M],
            [0, 0, 0, M],
        ]
        .into_iter()
        .map(Fe)
        .collect();
        // (2^256 - 1) * ceil(2^256 / 37) forces the rare second carry fold in
        // the reduction (as does (2^256 - 1)^2).
        let mut b = [0u64; 4];
        let mut rem: U = 1;
        for limb in b.iter_mut().rev() {
            let cur = rem << 64;
            *limb = (cur / 37) as u64;
            rem = cur % 37;
        }
        b[0] += 1;
        v.push(Fe(b));
        v
    }

    fn random(rng: &mut Rng) -> Fe {
        Fe([rng.u64(), rng.u64(), rng.u64(), rng.u64()])
    }

    /// The register-resident loop against repeated `square` (itself checked
    /// against the reference), bit for bit, with the special values.
    #[test]
    fn square_n_matches_repeated_squaring() {
        let mut rng = Rng::new(0x5a);
        let inputs = specials()
            .into_iter()
            .chain((0..200).map(|_| random(&mut rng)));
        for (i, a) in inputs.enumerate() {
            let n = [0, 1, 2, 3, 5, 13][i % 6];
            let want = (0..n).fold(a, |x, _| x.square());
            assert_eq!(a.square_n(n).0, want.0, "n = {n}, a = {:x?}", a.0);
        }
    }

    #[test]
    fn matches_reference() {
        let specials = specials();
        for a in &specials {
            for b in &specials {
                check(a, b);
            }
        }
        let mut rng = Rng::new(0x2551_9255_1925_5193);
        for i in 0..50_000 {
            let mut a = random(&mut rng);
            let mut b = random(&mut rng);
            if i % 4 == 1 {
                a.0[3] |= 1 << 63;
            }
            if i % 4 == 2 {
                b = specials[i % specials.len()];
            }
            check(&a, &b);
        }
    }

    #[test]
    fn inverse_and_square_root_power() {
        let mut rng = Rng::new(7);
        let mut values = specials();
        values.extend((0..500).map(|_| random(&mut rng)));
        for z in values {
            let want = if reduced(&z.0) == [0; 4] {
                [0; 4]
            } else {
                [1, 0, 0, 0]
            };
            assert_eq!(z.mul(&z.invert()).freeze().0, want, "invert {:x?}", z.0);
            // (z^((p-5)/8))^8 * z^4 = z^(p-1) = 1.
            let one = z.pow22523().square_n(3).mul(&z.square().square());
            assert_eq!(one.freeze().0, want, "pow22523 {:x?}", z.0);
        }
    }

    #[test]
    #[ignore = "benchmark"]
    fn bench_field() {
        use std::hint::black_box;
        let n = 1_000_000u32;
        let mut x = Fe([3, 5, 7, 11]);
        let y = Fe([13, 17, 19, 23]);
        let t = std::time::Instant::now();
        for _ in 0..n {
            x = black_box(x).square();
        }
        let sq = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..n {
            x = black_box(x).mul(&y);
        }
        let mu = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..n {
            x = black_box(x).add(&y);
        }
        let ad = t.elapsed().as_nanos() as f64 / n as f64;
        let t = std::time::Instant::now();
        for _ in 0..n {
            x = black_box(x).sub(&y);
        }
        let su = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "field (dependent chains): square {sq:.2} ns, mul {mu:.2} ns, add {ad:.2} ns, sub {su:.2} ns; {:?}",
            x.0[0]
        );
        let (mut a, mut b, mut c, mut d) = (x, y, Fe([1, 2, 3, 4]), Fe([5, 6, 7, 8]));
        let t = std::time::Instant::now();
        for _ in 0..n {
            a = a.mul(&y);
            b = b.mul(&y);
            c = c.mul(&y);
            d = d.mul(&y);
            (a, b, c, d) = black_box((a, b, c, d));
        }
        let four = t.elapsed().as_nanos() as f64 / n as f64 / 4.0;
        println!(
            "field: 4 independent mul chains: {four:.2} ns per mul {:?}",
            a.0[0] ^ b.0[0] ^ c.0[0] ^ d.0[0]
        );
    }

    #[test]
    fn bytes_round_trip() {
        let mut bytes: [u8; 32] = core::array::from_fn(|i| (i * 37 + 11) as u8);
        bytes[31] &= 0x7f;
        assert_eq!(Fe::from_bytes(&bytes).to_bytes(), bytes);
        // p encodes as 0 and p + 5 as 5.
        let p = Fe(P);
        assert_eq!(p.to_bytes(), [0; 32]);
        assert_eq!(p.add(&Fe([5, 0, 0, 0])).to_bytes()[..2], [5, 0]);
    }
}
