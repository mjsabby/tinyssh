//! SHA-512 (FIPS 180-4), for Ed25519. It only hashes short inputs (a key
//! exchange hash or an authentication request), so it is plain scalar code.

/// Round constants.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Initial hash value.
const H0: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// An incremental SHA-512 computation.
#[derive(Clone)]
pub(crate) struct Sha512 {
    state: [u64; 8],
    /// Input not yet compressed; always fewer than 128 bytes.
    block: [u8; 128],
    filled: usize,
    /// Bytes hashed so far.
    len: u64,
}

impl Sha512 {
    pub(crate) const fn new() -> Self {
        Self {
            state: H0,
            block: [0; 128],
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
            compress(&mut self.state, &self.block);
            self.filled = 0;
        }
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let blocks = data.chunks_exact(128);
        let rest = blocks.remainder();
        for block in blocks {
            compress(&mut self.state, block);
        }
        for (dst, src) in self.block.iter_mut().zip(rest) {
            *dst = *src;
        }
        self.filled = rest.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; 64] {
        // Padding: 0x80, zeros, and the 128-bit bit length in the last 16
        // bytes, spilling into a second block if fewer than 17 bytes are left.
        let mut tail = [0u8; 256];
        let pending = self.block.get(..self.filled).unwrap_or_default();
        for (dst, src) in tail.iter_mut().zip(pending) {
            *dst = *src;
        }
        if let Some(marker) = tail.get_mut(self.filled) {
            *marker = 0x80;
        }
        let blocks = match self.filled < 112 {
            true => 128,
            false => 256,
        };
        let padded = tail.get_mut(..blocks).unwrap_or_default();
        if let Some(length) = padded.last_chunk_mut::<16>() {
            let bits = (u128::from(self.len)).wrapping_mul(8);
            *length = bits.to_be_bytes();
        }
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for block in padded.chunks_exact(128) {
            compress(&mut self.state, block);
        }
        crate::rng::wipe(&mut tail);
        let mut digest = [0u8; 64];
        // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (out, word) in digest.chunks_exact_mut(8).zip(self.state) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        // Ed25519 hashes secrets: the seed and the signing nonce's input.
        crate::rng::wipe(&mut self.state);
        crate::rng::wipe(&mut self.block);
    }
}

/// SHA-512 of the concatenation of `parts`.
pub(crate) fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha512::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize()
}

/// The SHA-512 compression function on one 128-byte block (a shorter
/// `block` is padded with zeros, which never happens).
fn compress(state: &mut [u64; 8], block: &[u8]) {
    // The message schedule, kept as a ring of the last 16 words.
    let mut w = [0u64; 16];
    // https://github.com/rust-lang/rust/issues/165050 (as_chunks)
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes(bytes.try_into().unwrap_or_default());
    }
    let at = |w: &[u64; 16], i: usize| w.get(i & 15).copied().unwrap_or(0);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (t, k) in K.iter().enumerate() {
        let word = match t < 16 {
            true => at(&w, t),
            false => {
                // W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
                let w15 = at(&w, t.wrapping_add(1));
                let w2 = at(&w, t.wrapping_add(14));
                let s0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
                let s1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
                let next = at(&w, t)
                    .wrapping_add(s0)
                    .wrapping_add(at(&w, t.wrapping_add(9)))
                    .wrapping_add(s1);
                if let Some(slot) = w.get_mut(t & 15) {
                    *slot = next;
                }
                next
            }
        };
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(word);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        (h, g, f, e) = (g, f, e, d.wrapping_add(t1));
        (d, c, b, a) = (c, b, a, t1.wrapping_add(s0.wrapping_add(maj)));
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
    // The schedule is a function of the input, which can be secret.
    crate::rng::wipe(&mut w);
}

#[cfg(test)]
mod tests {
    use super::sha512;
    use sha2::Digest;

    fn hex(digest: [u8; 64]) -> String {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The examples of FIPS 180-4 / NIST, including padding that spills into
    /// a second block and a million-byte message fed in uneven pieces.
    #[test]
    fn nist_examples() {
        let cases: [(&[u8], &str); 4] = [
            (
                b"",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                b"abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335\
                 96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
                 501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ];
        for (message, digest) in cases {
            assert_eq!(hex(sha512(&[message])), digest);
        }
        let a = vec![b'a'; 1_000_000];
        let parts: Vec<&[u8]> = a.chunks(997).collect();
        assert_eq!(
            hex(sha512(&parts)),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
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
            let expected: [u8; 64] = sha2::Sha512::digest(message).into();
            for split in 0..=len {
                let (a, b) = message.split_at(split);
                assert_eq!(sha512(&[a, b]), expected, "length {len}, split at {split}");
            }
        }
    }
}
