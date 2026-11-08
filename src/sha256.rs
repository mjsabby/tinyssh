//! SHA-256 (FIPS 180-4) with the SHA-NI instructions.
//!
//! Only key exchange hashes (the exchange hash and key derivation), so this
//! favours clarity over speed: one compression loop, no unrolling by hand.

use core::arch::x86_64::*;

/// Initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Round constants (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// An incremental SHA-256 computation.
#[derive(Clone)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    /// Input not yet compressed; always fewer than 64 bytes.
    block: [u8; 64],
    filled: usize,
    /// Bytes hashed so far.
    len: u64,
}

impl Sha256 {
    pub(crate) const fn new() -> Self {
        Self {
            state: H0,
            block: [0; 64],
            filled: 0,
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let added = u64::try_from(data.len()).unwrap_or(u64::MAX);
        self.len = self.len.wrapping_add(added);
        let mut data = data;
        if self.filled > 0 {
            let free = self.block.get_mut(self.filled..).unwrap_or_default();
            let take = free.len().min(data.len());
            let (head, rest) = data.split_at_checked(take).unwrap_or((data, &[]));
            for (dst, src) in free.iter_mut().zip(head) {
                *dst = *src;
            }
            self.filled = self.filled.saturating_add(take);
            data = rest;
            if self.filled < self.block.len() {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.filled = 0;
        }
        let whole = data.len().saturating_sub(data.len() % 64);
        let (blocks, rest) = data.split_at_checked(whole).unwrap_or((&[], data));
        self.compress(blocks);
        for (dst, src) in self.block.iter_mut().zip(rest) {
            *dst = *src;
        }
        self.filled = rest.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        // Padding: 0x80, zeros, and the bit length in the last 8 bytes,
        // spilling into a second block if fewer than 9 bytes are left.
        let mut tail = [0u8; 128];
        let pending = self.block.get(..self.filled).unwrap_or_default();
        for (dst, src) in tail.iter_mut().zip(pending) {
            *dst = *src;
        }
        if let Some(marker) = tail.get_mut(self.filled) {
            *marker = 0x80;
        }
        let blocks = match self.filled < 56 {
            true => 64,
            false => 128,
        };
        let padded = tail.get_mut(..blocks).unwrap_or_default();
        if let Some(length) = padded.last_chunk_mut::<8>() {
            *length = bits.to_be_bytes();
        }
        self.compress(padded);
        crate::rng::wipe(&mut tail);
        let mut digest = [0u8; 32];
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Compresses whole 64-byte blocks (any partial block at the end is
    /// ignored).
    fn compress(&mut self, blocks: &[u8]) {
        // SAFETY: tinyssh is compiled with these target features (lib.rs).
        unsafe { compress(&mut self.state, blocks) };
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // Key derivation hashes the shared secret.
        crate::rng::wipe(&mut self.state);
        crate::rng::wipe(&mut self.block);
    }
}

/// The SHA-256 compression function on each 64-byte block of `blocks`.
///
/// SHA-NI keeps the state as two registers, `ABEF` and `CDGH` (words named
/// from the most significant lane down), and does two rounds per
/// `sha256rnds2`.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress(state: &mut [u32; 8], blocks: &[u8]) {
    // Byte-swaps each 32-bit word: SHA-256 reads message words big-endian.
    let swap = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);
    let [a, b, c, d, e, f, g, h] = *state;
    let to_vec = |w: [u32; 4]| {
        let [w0, w1, w2, w3] = w.map(u32::cast_signed);
        _mm_set_epi32(w3, w2, w1, w0)
    };
    let mut abef = to_vec([f, e, b, a]);
    let mut cdgh = to_vec([h, g, d, c]);
    // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for block in blocks.chunks_exact(64) {
        let (saved_abef, saved_cdgh) = (abef, cdgh);
        let words = block.as_ptr().cast::<__m128i>();
        // SAFETY: `block` holds 64 bytes, four 16-byte loads.
        let load = |i: usize| _mm_shuffle_epi8(unsafe { _mm_loadu_si128(words.add(i)) }, swap);
        // The last four groups of four message words.
        let (mut w0, mut w1, mut w2, mut w3) = (load(0), load(1), load(2), load(3));
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (i, k) in K.chunks_exact(4).enumerate() {
            // Groups 0-3 come from the block, later ones from the schedule
            // W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16].
            let w = match i < 4 {
                true => w0,
                false => {
                    let t =
                        _mm_add_epi32(_mm_sha256msg1_epu32(w0, w1), _mm_alignr_epi8::<4>(w3, w2));
                    _mm_sha256msg2_epu32(t, w3)
                }
            };
            (w0, w1, w2, w3) = (w1, w2, w3, w);
            // SAFETY: `k` holds four 32-bit constants, 16 bytes.
            let k = unsafe { _mm_loadu_si128(k.as_ptr().cast()) };
            let wk = _mm_add_epi32(w, k);
            cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
            abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32::<0x0E>(wk));
        }
        abef = _mm_add_epi32(abef, saved_abef);
        cdgh = _mm_add_epi32(cdgh, saved_cdgh);
    }
    let lanes = |v: __m128i| {
        let mut out = [0u32; 4];
        // SAFETY: 16 writable bytes.
        unsafe { _mm_storeu_si128(out.as_mut_ptr().cast(), v) };
        out
    };
    let [f, e, b, a] = lanes(abef);
    let [h, g, d, c] = lanes(cdgh);
    *state = [a, b, c, d, e, f, g, h];
}

#[cfg(test)]
mod tests {
    use super::Sha256;
    use sha2::Digest;

    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize()
    }

    fn hex(digest: [u8; 32]) -> String {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The examples of FIPS 180-4 / NIST, including padding that spills into
    /// a second block and a million-byte message fed in uneven pieces.
    #[test]
    fn nist_examples() {
        let cases: [(&[u8], &str); 4] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (message, digest) in cases {
            assert_eq!(hex(sha256(&[message])), digest);
        }
        let a = vec![b'a'; 1_000_000];
        let parts: Vec<&[u8]> = a.chunks(997).collect();
        assert_eq!(
            hex(sha256(&parts)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Every length up to 300 bytes, split at every point, against `sha2`.
    #[test]
    fn matches_sha2() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for len in 0..=data.len() {
            let message = &data[..len];
            let expected: [u8; 32] = sha2::Sha256::digest(message).into();
            for split in 0..=len {
                let (a, b) = message.split_at(split);
                assert_eq!(sha256(&[a, b]), expected, "length {len}, split at {split}");
            }
        }
    }
}
