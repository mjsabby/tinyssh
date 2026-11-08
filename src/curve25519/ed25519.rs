//! Ed25519 signatures (RFC 8032, section 5.1).

use super::edwards::{Point, mul_base};
use super::edwards4;
use super::scalar::Scalar;
use crate::rng::wipe;
use crate::sha512::{Sha512, sha512};

/// An Ed25519 key pair; the secret parts are wiped on drop.
pub(crate) struct SigningKey {
    seed: [u8; 32],
    /// s = clamp(SHA-512(seed)[..32]), reduced modulo L.
    scalar: Scalar,
    /// SHA-512(seed)[32..], which makes signing deterministic.
    prefix: [u8; 32],
    public: [u8; 32],
}

impl SigningKey {
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = sha512(&[seed]);
        let (mut s, mut prefix) = ([0u8; 32], [0u8; 32]);
        let (low, high) = h.split_at(32);
        s.copy_from_slice(low);
        prefix.copy_from_slice(high);
        let [first, .., last] = &mut s;
        *first &= 248;
        *last = (*last & 127) | 64;
        let key = Self {
            seed: *seed,
            scalar: Scalar::from_bytes_mod(&s),
            prefix,
            public: mul_base(&s).compress(),
        };
        wipe(&mut h);
        wipe(&mut s);
        wipe(&mut prefix);
        key
    }

    pub(crate) fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub(crate) fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The signature R || S of `message`.
    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut digest = sha512(&[&self.prefix, message]);
        let mut r = Scalar::from_wide(&digest);
        let mut r_bytes = r.to_bytes();
        let big_r = mul_base(&r_bytes).compress();
        let k = Scalar::from_wide(&sha512(&[&big_r, &self.public, message]));
        let s = Scalar::mul_add(&k, &self.scalar, &r);
        wipe(&mut digest);
        wipe(&mut r_bytes);
        r.wipe();
        let mut signature = [0u8; 64];
        let (sig_r, sig_s) = signature.split_at_mut(32);
        sig_r.copy_from_slice(&big_r);
        sig_s.copy_from_slice(&s.to_bytes());
        signature
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.prefix);
        self.scalar.wipe();
    }
}

/// Verifies `signature` over the concatenation of `parts` with `public`:
/// `[S]B = R + [k]A` without the cofactor, S must be below L, and keys of
/// small order are rejected. Not constant time: everything here is public.
pub(crate) fn verify(public: &[u8; 32], parts: &[&[u8]], signature: &[u8; 64]) -> bool {
    let Some(a) = Point::decompress(public) else {
        return false;
    };
    if a.is_small_order() {
        return false;
    }
    let (Some(r), Some(s)) = (signature.first_chunk::<32>(), signature.last_chunk::<32>()) else {
        return false;
    };
    let Some(s) = Scalar::from_canonical(s) else {
        return false;
    };
    let mut hash = Sha512::new();
    hash.update(r);
    hash.update(public);
    for part in parts {
        hash.update(part);
    }
    let k = Scalar::from_wide(&hash.finalize());
    // R' = [S]B - [k]A must encode exactly as R.
    edwards4::mul_vartime(&a.neg(), &k, &s).compress() == *r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Rng;
    use ed25519_dalek::ed25519::signature::{Signer, Verifier};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032, section 7.1: tests 1-3 and SHA(abc).
    #[test]
    fn rfc8032_vectors() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
            (
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
                 09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            ),
        ];
        for (seed, public, message, signature) in vectors {
            let key = SigningKey::from_seed(&hex(seed).try_into().unwrap());
            assert_eq!(key.public().to_vec(), hex(public));
            let message = hex(message);
            let signature: [u8; 64] = hex(signature).try_into().unwrap();
            assert_eq!(key.sign(&message), signature);
            assert!(verify(&key.public(), &[&message], &signature));
        }
    }

    /// Keys, signatures and verification against ed25519-dalek, including
    /// tampered signatures and messages split into several parts.
    #[test]
    fn matches_dalek() {
        let mut rng = Rng::new(0xed25519);
        for i in 0..300usize {
            let seed = rng.bytes::<32>();
            let message: Vec<u8> = (0..i).map(|_| rng.u64() as u8).collect();
            let ours = SigningKey::from_seed(&seed);
            let dalek = ed25519_dalek::SigningKey::from_bytes(&seed);
            assert_eq!(ours.public(), dalek.verifying_key().to_bytes());
            let signature = ours.sign(&message);
            assert_eq!(signature, dalek.sign(&message).to_bytes());
            let (head, tail) = message.split_at(i / 3);
            assert!(verify(&ours.public(), &[head, tail], &signature));
            // Any flipped bit must fail, for us and for dalek.
            let mut bad = signature;
            bad[rng.u64() as usize % 64] ^= 1 << (rng.u64() % 8);
            let dalek_ok = dalek
                .verifying_key()
                .verify(&message, &ed25519_dalek::Signature::from_bytes(&bad))
                .is_ok();
            assert!(!verify(&ours.public(), &[&message], &bad));
            assert!(!dalek_ok);
            let mut other = message.clone();
            other.push(0);
            assert!(!verify(&ours.public(), &[&other], &signature));
        }
    }

    /// `taskset -c 2 cargo test --release --lib -- --ignored --nocapture bench`
    #[test]
    #[ignore = "benchmark"]
    fn bench_ed25519() {
        use super::super::tests::time_ns;
        use std::hint::black_box;
        let key = SigningKey::from_seed(&[3; 32]);
        let dalek = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let message = [0x5a; 32]; // the size of a key exchange hash
        let signature = key.sign(&message);
        let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature);
        let public = key.public();
        let rows = [
            (
                "sign",
                time_ns(|| _ = black_box(key.sign(black_box(&message)))),
                time_ns(|| _ = black_box(dalek.sign(black_box(&message)))),
            ),
            // Both decode the public key each time, as SSH authentication
            // does.
            (
                "verify",
                time_ns(|| assert!(verify(black_box(&public), &[&message], &signature))),
                time_ns(|| {
                    let key = ed25519_dalek::VerifyingKey::from_bytes(black_box(&public));
                    assert!(key.unwrap().verify(&message, &dalek_signature).is_ok())
                }),
            ),
            (
                "from_seed",
                time_ns(|| _ = black_box(SigningKey::from_seed(black_box(&[3; 32])))),
                time_ns(|| {
                    _ = black_box(ed25519_dalek::SigningKey::from_bytes(black_box(&[3; 32])))
                }),
            ),
        ];
        for (name, ours, dalek) in rows {
            println!("ed25519 {name:<10} ours {ours:>6.0} ns, ed25519-dalek {dalek:>6.0} ns");
        }
    }

    /// S >= L (S + L is the classic malleability) and small-order keys are
    /// rejected; so are keys that do not decode.
    #[test]
    fn rejects_malleable_and_weak() {
        let key = SigningKey::from_seed(&[7; 32]);
        let signature = key.sign(b"message");
        assert!(verify(&key.public(), &[b"message"], &signature));
        // S + L
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut malleable = signature;
        let mut carry = 0u16;
        for (s, l) in malleable[32..].iter_mut().zip(L) {
            let v = *s as u16 + l as u16 + carry;
            *s = v as u8;
            carry = v >> 8;
        }
        assert!(!verify(&key.public(), &[b"message"], &malleable));
        // The identity as a key, with the signature (R = identity, S = 0)
        // that verifies for every message under the cofactorless equation.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut trivial = [0u8; 64];
        trivial[0] = 1;
        assert!(!verify(&identity, &[b"anything"], &trivial));
        // y = 2 is not a point.
        let mut invalid = [0u8; 32];
        invalid[0] = 2;
        assert!(!verify(&invalid, &[b"message"], &signature));
    }
}
