//! AES-128-GCM with VAES and VPCLMULQDQ, the 256-bit AVX2 forms of the
//! AES-NI and carry-less multiplication instructions (Zen 3+, Ice Lake+).
//!
//! It replaces the `aes-gcm` crate, which could use neither on such CPUs: its
//! GHASH only has a 128-bit PCLMULQDQ backend, and its CPU detection
//! (`cpufeatures`) treats VAES as an AVX-512 feature. It was about 2.5 times
//! slower; profiling had put it at half of the server's cycles.
//!
//! * AES-CTR encrypts 16 counter blocks (eight registers) per iteration.
//! * GHASH is computed as POLYVAL (RFC 8452, Appendix A): blocks are
//!   byte-reversed and the hash key is multiplied by x, which turns GCM's
//!   bit-reflected field into one where carry-less products need no shifts.
//!   Eight blocks are multiplied by H^8..H^1 and reduced once, with
//!   POLYVAL's Montgomery reduction (two multiplications by
//!   x^63 + x^62 + x^57).
//! * Decryption authenticates first, so a forged packet is left untouched.
//!
//! Nothing branches on or indexes by keys or data.

use core::arch::x86_64::*;

/// Longest input accepted, far below where GCM's 32-bit block counter would
/// wrap (2^32 blocks).
const MAX_LEN: usize = 1 << 32;

/// AES-128-GCM keys for one direction.
pub(crate) struct Gcm {
    /// AES-128 round keys, repeated in both 128-bit lanes.
    rk: [__m256i; 11],
    /// Hash key powers for eight blocks, in block order:
    /// `[H^8 | H^7], [H^6 | H^5], [H^4 | H^3], [H^2 | H^1]`.
    eight: [__m256i; 4],
    /// `eight` with the two 64-bit halves of each power XORed together, for
    /// Karatsuba multiplication.
    eight_folded: [__m256i; 4],
    /// `powers[i]` is H^(i+1), for the last blocks of an input.
    powers: [__m128i; 8],
}

impl Gcm {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        // SAFETY: tinyssh is compiled with these target features (lib.rs).
        unsafe { Self::init(key) }
    }

    /// Encrypts `data` in place and returns the tag.
    pub(crate) fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Option<[u8; 16]> {
        if data.len() > MAX_LEN || aad.len() > MAX_LEN {
            return None;
        }
        // SAFETY: tinyssh is compiled with these target features (lib.rs).
        Some(unsafe { self.seal_inner(nonce, aad, data) })
    }

    /// Checks `tag` and, only if it is valid, decrypts `data` in place.
    pub(crate) fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        if data.len() > MAX_LEN || aad.len() > MAX_LEN {
            return false;
        }
        // SAFETY: tinyssh is compiled with these target features (lib.rs).
        unsafe { self.open_inner(nonce, aad, data, tag) }
    }
}

impl Gcm {
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn init(key: &[u8; 16]) -> Self {
        let mut rk = [_mm256_setzero_si256(); 11];
        for (wide, round_key) in rk.iter_mut().zip(expand_key(load(key))) {
            *wide = _mm256_broadcastsi128_si256(round_key);
        }
        // POLYVAL's key for GHASH key H = AES(0): mulX(ByteReverse(H)).
        let h = mul_x(reverse(encrypt_block(&rk, _mm_setzero_si128())));
        let mut powers = [h; 8];
        let mut power = h;
        for slot in powers.iter_mut().skip(1) {
            power = dot(power, h);
            *slot = power;
        }
        let [h1, h2, h3, h4, h5, h6, h7, h8] = powers;
        let eight = [pair(h8, h7), pair(h6, h5), pair(h4, h3), pair(h2, h1)];
        let mut eight_folded = eight;
        for power in eight_folded.iter_mut() {
            *power = fold_halves(*power);
        }
        Self {
            rk,
            eight,
            eight_folded,
            powers,
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn seal_inner(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let j0 = j0(nonce);
        self.ctr(j0, data);
        store(self.tag(j0, aad, data))
    }

    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn open_inner(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let j0 = j0(nonce);
        let diff = _mm_xor_si128(self.tag(j0, aad, data), load(tag));
        // All 16 bytes are compared at once, in constant time.
        if _mm_testz_si128(diff, diff) == 0 {
            return false;
        }
        self.ctr(j0, data);
        true
    }

    /// The tag: AES(J0) xor GHASH(aad, data, lengths).
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn tag(&self, j0: __m128i, aad: &[u8], data: &[u8]) -> __m128i {
        let bits = |n: usize| u128::from(u64::try_from(n).unwrap_or(u64::MAX).wrapping_mul(8));
        let lengths = (bits(aad.len()).wrapping_shl(64) | bits(data.len())).to_be_bytes();
        let acc = self.ghash(_mm_setzero_si128(), aad);
        let acc = self.ghash(acc, data);
        let acc = self.ghash(acc, &lengths);
        _mm_xor_si128(encrypt_block(&self.rk, j0), reverse(acc))
    }

    /// XORs the key stream for the counter blocks after `j0` into `data`.
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn ctr(&self, j0: __m128i, data: &mut [u8]) {
        let rev = reverse_lanes();
        // Counter blocks are kept byte-reversed: GCM's 32-bit big-endian
        // block counter is then the low dword of each lane, where vpaddd
        // increments it modulo 2^32 as inc32 requires.
        let two = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 2);
        let first = _mm256_broadcastsi128_si256(reverse(j0));
        let mut counter = _mm256_add_epi32(first, _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 1));
        let mut next = || {
            let block = _mm256_shuffle_epi8(counter, rev);
            counter = _mm256_add_epi32(counter, two);
            block
        };
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let mut chunks = data.chunks_exact_mut(256);
        for chunk in &mut chunks {
            let mut stream = [_mm256_setzero_si256(); 8];
            for block in stream.iter_mut() {
                *block = next();
            }
            self.encrypt(&mut stream);
            let words = chunk.as_mut_ptr().cast::<__m256i>();
            for (i, key) in stream.into_iter().enumerate() {
                // SAFETY: `chunk` holds 256 bytes, eight 32-byte words.
                unsafe { xor_into(words.add(i), key) };
            }
        }
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let mut pairs = chunks.into_remainder().chunks_exact_mut(32);
        for pair in &mut pairs {
            let mut stream = [next()];
            self.encrypt(&mut stream);
            let [key] = stream;
            // SAFETY: `pair` holds 32 bytes.
            unsafe { xor_into(pair.as_mut_ptr().cast(), key) };
        }
        let tail = pairs.into_remainder();
        if !tail.is_empty() {
            let mut stream = [next()];
            self.encrypt(&mut stream);
            let [key] = stream;
            let mut bytes = [0u8; 32];
            // SAFETY: `bytes` holds 32 bytes.
            unsafe { _mm256_storeu_si256(bytes.as_mut_ptr().cast(), key) };
            for (byte, key) in tail.iter_mut().zip(bytes) {
                *byte ^= key;
            }
        }
    }

    /// AES-128 on `N` registers of two blocks each, interleaved so the
    /// rounds of different registers overlap.
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn encrypt<const N: usize>(&self, blocks: &mut [__m256i; N]) {
        let [first, middle @ .., last] = &self.rk;
        for block in blocks.iter_mut() {
            *block = _mm256_xor_si256(*block, *first);
        }
        for round_key in middle {
            for block in blocks.iter_mut() {
                *block = _mm256_aesenc_epi128(*block, *round_key);
            }
        }
        for block in blocks.iter_mut() {
            *block = _mm256_aesenclast_epi128(*block, *last);
        }
    }

    /// Absorbs `data`, zero-padded to whole blocks, into the POLYVAL state
    /// `acc`.
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn ghash(&self, acc: __m128i, data: &[u8]) -> __m128i {
        let mut acc = acc;
        let rev = reverse_lanes();
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let mut groups = data.chunks_exact(128);
        for group in &mut groups {
            let words = group.as_ptr().cast::<__m256i>();
            let mut sum = Wide::zero();
            let powers = self.eight.iter().zip(&self.eight_folded);
            // Word 0, which needs the previous group's result, goes last, so
            // that the other products overlap that reduction.
            for (i, (power, folded)) in powers.enumerate().rev() {
                // SAFETY: `group` holds 128 bytes, four 32-byte words.
                let mut x = _mm256_shuffle_epi8(unsafe { _mm256_loadu_si256(words.add(i)) }, rev);
                if i == 0 {
                    x = _mm256_xor_si256(x, _mm256_zextsi128_si256(acc));
                }
                sum.mul_add(x, *power, *folded);
            }
            acc = sum.reduce();
        }
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let mut blocks = groups.remainder().chunks_exact(16);
        let count = blocks.len();
        if count > 0 {
            // The first remaining block is multiplied by H^count, the last by H.
            let powers = self.powers.iter().take(count).rev();
            let mut sum = Narrow::zero();
            for (i, (block, power)) in (&mut blocks).zip(powers).enumerate() {
                // SAFETY: `block` holds 16 bytes.
                let mut x = reverse(unsafe { _mm_loadu_si128(block.as_ptr().cast()) });
                if i == 0 {
                    x = _mm_xor_si128(x, acc);
                }
                sum.mul_add(x, *power);
            }
            acc = sum.reduce();
        }
        let tail = blocks.remainder();
        if !tail.is_empty() {
            let mut block = [0u8; 16];
            for (byte, data) in block.iter_mut().zip(tail) {
                *byte = *data;
            }
            let [h, ..] = self.powers;
            acc = dot(_mm_xor_si128(acc, reverse(load(&block))), h);
        }
        acc
    }
}

impl Drop for Gcm {
    /// Overwrites the round keys and hash key powers (as `aes-gcm` does with
    /// its `zeroize` feature).
    fn drop(&mut self) {
        let wide = self
            .rk
            .iter_mut()
            .chain(&mut self.eight)
            .chain(&mut self.eight_folded);
        for v in wide {
            // SAFETY: `v` is a valid, exclusive reference; zero is a valid
            // `__m256i`.
            unsafe { core::ptr::write_volatile(v, core::mem::zeroed()) };
        }
        for v in self.powers.iter_mut() {
            // SAFETY: as above, for `__m128i`.
            unsafe { core::ptr::write_volatile(v, core::mem::zeroed()) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Unreduced carry-less products, two blocks per register, with Karatsuba's
/// middle term: `hi·x^128 + (mid + lo + hi)·x^64 + lo` in each lane.
///
/// Three 64-bit multiplications per block instead of four: on Zen 3 the
/// multiplier (one pipe, two cycles per 256-bit operation) bounds GHASH.
#[derive(Clone, Copy)]
struct Wide {
    lo: __m256i,
    mid: __m256i,
    hi: __m256i,
}

impl Wide {
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn zero() -> Self {
        let zero = _mm256_setzero_si256();
        Self {
            lo: zero,
            mid: zero,
            hi: zero,
        }
    }

    /// Adds the product of `x` and `h`, lane by lane; `h_folded` is
    /// [`fold_halves`] of `h`.
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn mul_add(&mut self, x: __m256i, h: __m256i, h_folded: __m256i) {
        let mid = _mm256_clmulepi64_epi128::<0x00>(fold_halves(x), h_folded);
        self.lo = _mm256_xor_si256(self.lo, _mm256_clmulepi64_epi128::<0x00>(x, h));
        self.mid = _mm256_xor_si256(self.mid, mid);
        self.hi = _mm256_xor_si256(self.hi, _mm256_clmulepi64_epi128::<0x11>(x, h));
    }

    /// Adds the two lanes and reduces the sum.
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn reduce(self) -> __m128i {
        let fold =
            |v: __m256i| _mm_xor_si128(_mm256_castsi256_si128(v), _mm256_extracti128_si256::<1>(v));
        let (lo, hi) = (fold(self.lo), fold(self.hi));
        // (x0+x1)(h0+h1) = x0h0 + x1h1 + (x0h1 + x1h0): recover the middle.
        let mid = _mm_xor_si128(fold(self.mid), _mm_xor_si128(lo, hi));
        reduce(lo, mid, hi)
    }
}

/// XORs the two 64-bit halves of each 128-bit lane (into both halves).
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn fold_halves(v: __m256i) -> __m256i {
    _mm256_xor_si256(v, _mm256_shuffle_epi32::<0x4E>(v))
}

/// Unreduced carry-less products of single blocks.
#[derive(Clone, Copy)]
struct Narrow {
    lo: __m128i,
    mid: __m128i,
    hi: __m128i,
}

impl Narrow {
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn zero() -> Self {
        let zero = _mm_setzero_si128();
        Self {
            lo: zero,
            mid: zero,
            hi: zero,
        }
    }

    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn mul_add(&mut self, x: __m128i, h: __m128i) {
        let cross = _mm_xor_si128(
            _mm_clmulepi64_si128::<0x01>(x, h),
            _mm_clmulepi64_si128::<0x10>(x, h),
        );
        self.lo = _mm_xor_si128(self.lo, _mm_clmulepi64_si128::<0x00>(x, h));
        self.mid = _mm_xor_si128(self.mid, cross);
        self.hi = _mm_xor_si128(self.hi, _mm_clmulepi64_si128::<0x11>(x, h));
    }

    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn reduce(self) -> __m128i {
        reduce(self.lo, self.mid, self.hi)
    }
}

/// POLYVAL's product `a·b·x^-128` (RFC 8452's `dot`).
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn dot(a: __m128i, b: __m128i) -> __m128i {
    let mut product = Narrow::zero();
    product.mul_add(a, b);
    product.reduce()
}

/// Montgomery reduction of `hi·x^128 + mid·x^64 + lo` to `· x^-128` modulo
/// POLYVAL's polynomial Q = x^128 + x^127 + x^126 + x^121 + 1.
///
/// Q ≡ 1 (mod x^64), so each step adds the low 64 bits `m` times Q, which
/// clears them, and drops them. `m·Q` is `m·x^128 + m·(x^63+x^62+x^57)·x^64
/// + m`, so only one 64×64 multiplication is needed per step.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn reduce(lo: __m128i, mid: __m128i, hi: __m128i) -> __m128i {
    let lo = _mm_xor_si128(lo, _mm_slli_si128::<8>(mid));
    let hi = _mm_xor_si128(hi, _mm_srli_si128::<8>(mid));
    let poly = _mm_set_epi64x(0, 0xC200_0000_0000_0000_u64.cast_signed());
    let t = _mm_clmulepi64_si128::<0x00>(lo, poly);
    let lo = _mm_xor_si128(_mm_shuffle_epi32::<0x4E>(lo), t);
    let t = _mm_clmulepi64_si128::<0x00>(lo, poly);
    let lo = _mm_xor_si128(_mm_shuffle_epi32::<0x4E>(lo), t);
    _mm_xor_si128(lo, hi)
}

/// `v·x` in POLYVAL's field (RFC 8452's `mulX_POLYVAL`). Key setup only.
fn mul_x(v: __m128i) -> __m128i {
    let v = u128::from_le_bytes(store(v));
    // x^128 = x^127 + x^126 + x^121 + 1, added only if the top bit was set.
    let carry = 0u128.wrapping_sub(v.wrapping_shr(127));
    let poly = 0xC200_0000_0000_0000_0000_0000_0000_0001_u128;
    load(&(v.wrapping_shl(1) ^ (carry & poly)).to_le_bytes())
}

/// AES-128 key expansion (FIPS 197) with AESKEYGENASSIST.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn expand_key(key: __m128i) -> [__m128i; 11] {
    #[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
    fn next<const RCON: i32>(key: __m128i) -> __m128i {
        let word = _mm_shuffle_epi32::<0xFF>(_mm_aeskeygenassist_si128::<RCON>(key));
        // Prefix XOR of the four words: w0, w0^w1, w0^w1^w2, w0^..^w3.
        let shifted = _mm_slli_si128::<4>(key);
        let key = _mm_xor_si128(key, shifted);
        let shifted = _mm_slli_si128::<4>(shifted);
        let key = _mm_xor_si128(key, shifted);
        let shifted = _mm_slli_si128::<4>(shifted);
        _mm_xor_si128(_mm_xor_si128(key, shifted), word)
    }
    let k1 = next::<0x01>(key);
    let k2 = next::<0x02>(k1);
    let k3 = next::<0x04>(k2);
    let k4 = next::<0x08>(k3);
    let k5 = next::<0x10>(k4);
    let k6 = next::<0x20>(k5);
    let k7 = next::<0x40>(k6);
    let k8 = next::<0x80>(k7);
    let k9 = next::<0x1B>(k8);
    let k10 = next::<0x36>(k9);
    [key, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10]
}

/// AES-128 on one block.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn encrypt_block(rk: &[__m256i; 11], block: __m128i) -> __m128i {
    let [first, middle @ .., last] = rk;
    let mut block = _mm_xor_si128(block, _mm256_castsi256_si128(*first));
    for round_key in middle {
        block = _mm_aesenc_si128(block, _mm256_castsi256_si128(*round_key));
    }
    _mm_aesenclast_si128(block, _mm256_castsi256_si128(*last))
}

/// The pre-counter block for a 96-bit nonce: `nonce || 0x00000001`.
fn j0(nonce: &[u8; 12]) -> __m128i {
    let mut block = [0u8; 16];
    for (byte, n) in block.iter_mut().zip(nonce) {
        *byte = *n;
    }
    if let Some(last) = block.last_mut() {
        *last = 1;
    }
    load(&block)
}

/// `[a | b]`: `a` in the low lane (the first block in memory).
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn pair(a: __m128i, b: __m128i) -> __m256i {
    _mm256_set_m128i(b, a)
}

/// Reverses the 16 bytes of a block.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn reverse(v: __m128i) -> __m128i {
    _mm_shuffle_epi8(
        v,
        _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    )
}

/// Shuffle mask reversing the bytes of each 128-bit lane.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
fn reverse_lanes() -> __m256i {
    _mm256_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    )
}

fn load(bytes: &[u8; 16]) -> __m128i {
    // SAFETY: 16 readable bytes; SSE2 is part of x86-64.
    unsafe { _mm_loadu_si128(bytes.as_ptr().cast()) }
}

fn store(v: __m128i) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    // SAFETY: 16 writable bytes; SSE2 is part of x86-64.
    unsafe { _mm_storeu_si128(bytes.as_mut_ptr().cast(), v) };
    bytes
}

/// `*word ^= key` for an unaligned 32-byte word.
///
/// # Safety
///
/// `word` must be valid for reading and writing 32 bytes, and AVX available.
#[target_feature(enable = "aes,pclmulqdq,avx2,vaes,vpclmulqdq")]
unsafe fn xor_into(word: *mut __m256i, key: __m256i) {
    // SAFETY: guaranteed by the caller.
    unsafe { _mm256_storeu_si256(word, _mm256_xor_si256(_mm256_loadu_si256(word), key)) };
}

#[cfg(test)]
mod tests {
    use super::Gcm;
    use aes_gcm::aead::array::Array;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `aes-gcm` encryption: the reference.
    fn reference(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let gcm = Aes128Gcm::new(&Array::from(*key));
        let tag = gcm
            .encrypt_inout_detached(&Array::from(*nonce), aad, data.into())
            .unwrap();
        tag.into()
    }

    /// `taskset -c 2 cargo test --release --lib -- --ignored --nocapture bench_gcm`
    #[test]
    #[ignore = "benchmark"]
    fn bench_gcm() {
        let gcm = Gcm::new(&[7; 16]);
        let mut data = vec![0x5au8; 32 * 1024];
        let (nonce, aad) = ([1u8; 12], [0u8; 4]);
        let mut tag = [0u8; 16];
        for _ in 0..100 {
            tag = gcm.seal(&nonce, &aad, &mut data).unwrap();
        }
        let rounds = 20_000;
        let start = std::time::Instant::now();
        for _ in 0..rounds {
            tag = gcm
                .seal(&nonce, &aad, std::hint::black_box(&mut data))
                .unwrap();
        }
        let seal = (rounds * data.len()) as f64 / start.elapsed().as_nanos() as f64;
        let start = std::time::Instant::now();
        for _ in 0..rounds {
            // Fails after the first round (data changes), but still hashes everything.
            std::hint::black_box(gcm.open(&nonce, &aad, std::hint::black_box(&mut data), &tag));
        }
        let open = (rounds * data.len()) as f64 / start.elapsed().as_nanos() as f64;
        println!("gcm 32 KiB: seal {seal:.2} GB/s, open (tag check) {open:.2} GB/s");
    }

    /// Test cases 1-4 (AES-128) of the GCM specification by McGrew and Viega.
    #[test]
    fn gcm_specification_vectors() {
        let k3 = "feffe9928665731c6d6a8f9467308308";
        let iv3 = "cafebabefacedbaddecaf888";
        let p3 = "d9313225f88406e5a55909c5aff5269a 86a7a9531534f7da2e4c303d8a318a72
                  1c3c0c95956809532fcf0e2449a6b525 b16aedf5aa0de657ba637b391aafd255";
        let c3 = "42831ec2217774244b7221b784d0d49c e3aa212f2c02a4e035c17e2329aca12e
                  21d514b25466931c7d8f6a5aac84aa05 1ba30b396a0aac973d58e091473f5985";
        let cases = [
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                "",
                "",
                "",
                "58e2fccefa7e3061367f1d57a4e7455a",
            ),
            (
                "00000000000000000000000000000000",
                "000000000000000000000000",
                "00000000000000000000000000000000",
                "",
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (k3, iv3, p3, "", c3, "4d5c2af327cd64a62cf35abd2ba6fab4"),
            (
                k3,
                iv3,
                &p3[..p3.len() - 8],
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                &c3[..c3.len() - 8],
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
        ];
        for (key, nonce, plain, aad, cipher, tag) in cases {
            let key: [u8; 16] = hex(key).try_into().unwrap();
            let nonce: [u8; 12] = hex(nonce).try_into().unwrap();
            let (plain, aad, cipher, tag) = (hex(plain), hex(aad), hex(cipher), hex(tag));
            let mut check = plain.clone();
            assert_eq!(
                reference(&key, &nonce, &aad, &mut check)[..],
                tag[..],
                "vector vs aes-gcm"
            );
            let gcm = Gcm::new(&key);
            let mut data = plain.clone();
            assert_eq!(gcm.seal(&nonce, &aad, &mut data).unwrap()[..], tag[..]);
            assert_eq!(data, cipher);
            assert!(gcm.open(&nonce, &aad, &mut data, &tag.clone().try_into().unwrap()));
            assert_eq!(data, plain);
        }
    }

    /// Every length up to 600 bytes (all partial-block and group-boundary
    /// cases) and a few large ones, against `aes-gcm`; tampering with the
    /// tag, ciphertext or associated data must fail and change nothing.
    #[test]
    fn matches_aes_gcm_on_random_inputs() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut random = move |out: &mut [u8]| {
            for byte in out {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = (state >> 24) as u8;
            }
        };
        let lengths = (0..=600).chain([1023, 1024, 1025, 4095, 4096, 4097, 32_768, 32_784, 35_000]);
        for (round, len) in lengths.enumerate() {
            let (mut key, mut nonce) = ([0u8; 16], [0u8; 12]);
            random(&mut key);
            random(&mut nonce);
            let gcm = Gcm::new(&key);
            let mut aad = vec![0u8; [0, 4, 4, 13, 16, 17, 48][round % 7]];
            let mut plain = vec![0u8; len];
            random(&mut aad);
            random(&mut plain);
            let mut expected = plain.clone();
            let expected_tag = reference(&key, &nonce, &aad, &mut expected);
            let mut data = plain.clone();
            let tag = gcm.seal(&nonce, &aad, &mut data).unwrap();
            assert_eq!(
                (&data, tag),
                (&expected, expected_tag),
                "length {len}, aad {}",
                aad.len()
            );

            let mut bad_tag = tag;
            bad_tag[round % 16] ^= 1 << (round % 8);
            assert!(!gcm.open(&nonce, &aad, &mut data, &bad_tag));
            if !data.is_empty() {
                data[round % len] ^= 0x80;
                assert!(!gcm.open(&nonce, &aad, &mut data, &tag));
                data[round % len] ^= 0x80;
            }
            if !aad.is_empty() {
                let i = round % aad.len();
                aad[i] ^= 1;
                assert!(!gcm.open(&nonce, &aad, &mut data, &tag));
                aad[i] ^= 1;
            }
            assert_eq!(data, expected, "failed opens must not touch the data");
            assert!(gcm.open(&nonce, &aad, &mut data, &tag));
            assert_eq!(data, plain);
        }
    }
}
