//! Curve25519: X25519 key agreement (RFC 7748) and Ed25519 signatures
//! (RFC 8032), for the CPUs tinyssh is compiled for.
//!
//! * [`field`]: arithmetic modulo 2^255 - 19 with MULX, ADCX and ADOX.
//! * [`ladder`](mod@ladder): the Montgomery ladder for X25519 shared secrets,
//!   four field elements at a time in AVX2 registers.
//! * [`edwards::mul_base`]: multiples of the base point, for Ed25519 keys and
//!   signatures and X25519 public keys, from a precomputed table
//!   ([`base_table`]).
//! * [`edwards`], [`scalar`] and [`ed25519`]: the rest of Ed25519, with
//!   variable-time arithmetic only for verifying signatures.
//!
//! The field arithmetic and the ladder are ported from a C++ implementation
//! that is faster than OpenSSL's and libsodium's X25519 on Zen 3.

mod base_table;
pub(crate) mod ed25519;
mod edwards;
mod edwards4;
mod field;
mod ladder;
mod scalar;

use field::{Fe, barrier};
use ladder::ladder;

/// A key pair's public key X25519(`scalar`, 9) and its shared secret
/// X25519(`scalar`, `point`) (RFC 7748, section 5), or `None` if the shared
/// secret is all zero, which happens exactly when `point` has small order.
/// RFC 8731 requires the key exchange to be aborted then.
pub(crate) fn x25519_pair(scalar: &[u8; 32], point: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let (public, shared) = pair(scalar, point);
    // Only whether the result is zero is revealed, not where it is nonzero.
    let any = shared.iter().fold(0, |acc, &b| acc | b);
    (barrier(u64::from(any)) != 0).then_some((public, shared))
}

/// [`x25519_pair`] without the check, in constant time. The public key is
/// `[k]B` on edwards25519 mapped to u = (Z + Y) / (Z - Y), the shared secret
/// the ladder's x2 / z2: one inversion of (Z - Y) z2 serves both. When the
/// shared secret is zero (z2 = 0) the public key comes out zero too, but
/// then neither is used. Z - Y is never zero: a clamped scalar is not a
/// multiple of the group order, so `[k]B` is not the identity.
fn pair(scalar: &[u8; 32], point: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut u = *point;
    // Bit 255 is ignored; other non-canonical values are used as they are.
    if let Some(top) = u.last_mut() {
        *top &= 0x7f;
    }
    let mut k = clamp(scalar);
    let base = edwards::mul_base(&k);
    let x = ladder(&k, &Fe::from_bytes(&u));
    crate::rng::wipe(&mut k);
    let den = base.z.sub(&base.y);
    let inv = den.mul(&x.z2).invert();
    let public = base.z.add(&base.y).mul(&inv.mul(&x.z2)).to_bytes();
    let shared = x.x2.mul(&inv.mul(&den)).to_bytes();
    (public, shared)
}

/// X25519(`scalar`, `point`), or `None` if it is all zero: the reference for
/// the shared secret of [`x25519_pair`].
#[cfg(test)]
pub(crate) fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    let mut u = *point;
    // Bit 255 is ignored; other non-canonical values are used as they are.
    if let Some(top) = u.last_mut() {
        *top &= 0x7f;
    }
    let mut k = clamp(scalar);
    let x = ladder(&k, &Fe::from_bytes(&u));
    crate::rng::wipe(&mut k);
    let shared = x.x2.mul(&x.z2.invert()).to_bytes();
    // Only whether the result is zero is revealed, not where it is nonzero.
    let any = shared.iter().fold(0, |acc, &b| acc | b);
    (barrier(u64::from(any)) != 0).then_some(shared)
}

/// The X25519 public key for `scalar`: X25519(`scalar`, 9), computed on
/// edwards25519 and mapped to the u-coordinate; the reference for the public
/// key of [`x25519_pair`].
#[cfg(test)]
pub(crate) fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = clamp(scalar);
    let public = edwards::mul_base(&k).to_montgomery();
    crate::rng::wipe(&mut k);
    public
}

/// The scalar X25519 multiplies by (RFC 7748, section 5).
fn clamp(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    let [low, .., high] = &mut k;
    *low &= 248;
    *high = (*high & 127) | 64;
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Rng;

    /// The u-coordinate of the base point.
    const NINE: [u8; 32] = {
        let mut nine = [0; 32];
        nine[0] = 9;
        nine
    };

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// RFC 7748, section 5.2.
    #[test]
    fn rfc7748_vectors() {
        let vectors = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            // u has bit 255 set, which must be ignored.
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (k, u, out) in vectors {
            assert_eq!(x25519(&hex(k), &hex(u)), Some(hex(out)));
        }
    }

    /// RFC 7748, section 5.2: k = u = 9, then repeatedly
    /// (k, u) = (X25519(k, u), k).
    fn iterate(n: u32) -> [u8; 32] {
        let (mut k, mut u) = (NINE, NINE);
        for _ in 0..n {
            (k, u) = (x25519(&k, &u).unwrap(), k);
        }
        k
    }

    #[test]
    fn rfc7748_iterations() {
        assert_eq!(
            iterate(1),
            hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
        assert_eq!(
            iterate(1000),
            hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    #[ignore = "slow; run with --release -- --ignored"]
    fn rfc7748_million_iterations() {
        assert_eq!(
            iterate(1_000_000),
            hex("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
        );
    }

    /// RFC 7748, section 6.1.
    #[test]
    fn rfc7748_diffie_hellman() {
        let alice: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob: [u8; 32] = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let (alice_public, bob_public) = (x25519_base(&alice), x25519_base(&bob));
        assert_eq!(
            alice_public,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice, &bob_public), Some(shared));
        assert_eq!(x25519(&bob, &alice_public), Some(shared));
    }

    /// u-coordinates around p and 2^255, with bit 255 set, and of small
    /// order (which must give `None`), against x25519-dalek.
    #[test]
    fn edge_points_match_dalek() {
        let p = field::tests::P;
        let small_order = [
            hex::<32>("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex::<32>("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ];
        let mut points: Vec<[u8; 32]> = Vec::new();
        let words = |w: [u64; 4]| -> [u8; 32] {
            core::array::from_fn(|i| (w[i / 8] >> (8 * (i % 8))) as u8)
        };
        let add = |w: [u64; 4], k: u64| -> [u64; 4] {
            let (w0, c) = w[0].overflowing_add(k);
            let (w1, c) = w[1].overflowing_add(c as u64);
            let (w2, c) = w[2].overflowing_add(c as u64);
            [w0, w1, w2, w[3].wrapping_add(c as u64)]
        };
        for small in [0, 1, 2, 9, 19, u64::MAX] {
            points.push(words([small, 0, 0, 0]));
        }
        for k in [0, 1, 2, 18, 19, 20] {
            points.push(words(add(p, k))); // p .. p + 20, around 2^255
            points.push(words(add([0, 0, 0, 1 << 63], k))); // 2^255 + k
        }
        points.push(words([u64::MAX - 1, u64::MAX, u64::MAX, u64::MAX >> 1])); // p - 1 + 2^255 - p ...
        points.push([0xff; 32]);
        points.push(words([u64::MAX - 18, u64::MAX, u64::MAX, u64::MAX])); // 2^256 - 19
        for s in small_order {
            points.push(s);
            let mut high = s;
            high[31] |= 0x80;
            points.push(high);
        }
        let mut rng = Rng::new(7748);
        let mut scalars = vec![[0u8; 32], [0xff; 32], NINE];
        scalars.extend((0..5).map(|_| rng.bytes::<32>()));
        for u in &points {
            for k in &scalars {
                let want = x25519_dalek::x25519(*k, *u);
                let want = (want != [0; 32]).then_some(want);
                assert_eq!(x25519(k, u), want, "k={k:02x?} u={u:02x?}");
                let public = x25519_dalek::x25519(*k, x25519_dalek::X25519_BASEPOINT_BYTES);
                assert_eq!(x25519_pair(k, u), want.map(|shared| (public, shared)));
            }
        }
    }

    /// Median nanoseconds per call over 25 rounds of 200 calls.
    pub(crate) fn time_ns(mut op: impl FnMut()) -> f64 {
        for _ in 0..200 {
            op();
        }
        let mut rounds: Vec<f64> = (0..25)
            .map(|_| {
                let start = std::time::Instant::now();
                for _ in 0..200 {
                    op();
                }
                start.elapsed().as_nanos() as f64 / 200.0
            })
            .collect();
        rounds.sort_by(f64::total_cmp);
        rounds[rounds.len() / 2]
    }

    /// `taskset -c 2 cargo test --release --lib -- --ignored --nocapture bench`
    #[test]
    #[ignore = "benchmark"]
    fn bench_x25519() {
        let mut rng = Rng::new(1);
        let (mut k, mut u) = (rng.bytes::<32>(), rng.bytes::<32>());
        // Each result feeds the next call so calls cannot overlap.
        let ours = time_ns(|| u = x25519(&k, &u).unwrap());
        let ours_base = time_ns(|| k = x25519_base(&k));
        let ours_pair = time_ns(|| (k, u) = x25519_pair(&k, &u).unwrap());
        let dalek = time_ns(|| u = x25519_dalek::x25519(k, u));
        // dalek's fixed-base path (its precomputed Edwards table).
        let dalek_base = time_ns(|| {
            let secret = x25519_dalek::StaticSecret::from(k);
            k = x25519_dalek::PublicKey::from(&secret).to_bytes();
        });
        println!("x25519:      ours {ours:.0} ns, x25519-dalek {dalek:.0} ns");
        println!("x25519_base: ours {ours_base:.0} ns, x25519-dalek {dalek_base:.0} ns");
        println!(
            "x25519_pair: ours {ours_pair:.0} ns (both: {:.0} ns), x25519-dalek {:.0} ns",
            ours + ours_base,
            dalek + dalek_base
        );
    }

    /// Valgrind's client request; outside Valgrind the magic sequence (four
    /// rotations adding up to 128 bits and a no-op exchange) does nothing.
    ///
    /// `bytes` is mutable so that the compiler cannot keep copies of it
    /// (made before the request) in registers, which keep their old state.
    fn valgrind(request: u64, bytes: &mut [u8]) {
        let args = [
            request,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        ];
        unsafe {
            core::arch::asm!(
                "rolq $3, %rdi", "rolq $13, %rdi", "rolq $61, %rdi", "rolq $51, %rdi", "xchgq %rbx, %rbx",
                inout("rdx") 0u64 => _, in("rax") args.as_ptr(), inout("rdi") 0u64 => _,
                options(att_syntax, nostack),
            )
        };
    }

    /// Memcheck reports any branch or memory address that depends on bytes
    /// marked undefined, so marking the secrets undefined checks that the
    /// code runs in constant time ("ctgrind"). Run the test binary as
    /// `valgrind --error-exitcode=1 <binary> --ignored --exact curve25519::tests::constant_time`
    /// and expect "ERROR SUMMARY: 0 errors".
    #[test]
    #[ignore = "run under valgrind"]
    fn constant_time() {
        const UNDEFINED: u64 = 0x4d43_0001; // VG_USERREQ__MAKE_MEM_UNDEFINED
        const DEFINED: u64 = 0x4d43_0002; // VG_USERREQ__MAKE_MEM_DEFINED
        let mut rng = Rng::new(1);
        let (mut k, mut u, mut seed) = (rng.bytes::<32>(), rng.bytes::<32>(), rng.bytes::<32>());
        for round in 0..2 {
            valgrind(UNDEFINED, &mut k);
            valgrind(UNDEFINED, &mut u);
            valgrind(UNDEFINED, &mut seed);
            // The all-zero check of `x25519_pair` branches by design.
            let (mut public, mut shared) = pair(&k, &u);
            let key = ed25519::SigningKey::from_seed(&seed);
            let mut signature = key.sign(b"exchange hash");
            let mut key_public = key.public();
            for out in [
                &mut shared[..],
                &mut public,
                &mut signature,
                &mut key_public,
            ] {
                valgrind(DEFINED, out);
            }
            valgrind(DEFINED, &mut k);
            valgrind(DEFINED, &mut u);
            valgrind(DEFINED, &mut seed);
            if round == 1 {
                assert!(ed25519::verify(
                    &key_public,
                    &[b"exchange hash"],
                    &signature
                ));
                assert_eq!(Some((public, shared)), x25519_pair(&k, &u));
                assert_eq!((public, Some(shared)), (x25519_base(&k), x25519(&k, &u)));
            }
        }
    }

    #[test]
    fn random_inputs_match_dalek() {
        let mut rng = Rng::new(25519);
        for i in 0..2000 {
            let k = rng.bytes::<32>();
            let mut u = rng.bytes::<32>();
            match i % 8 {
                1 => u[1..].fill(0xff), // u >= p
                2 => u[..31].fill(0),   // tiny limbs
                _ => {}
            }
            let want = x25519_dalek::x25519(k, u);
            let want = (want != [0; 32]).then_some(want);
            assert_eq!(x25519(&k, &u), want, "k={k:02x?} u={u:02x?}");
            let public = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
            assert_eq!(x25519_pair(&k, &u), want.map(|shared| (public, shared)));
            if i % 4 == 0 {
                assert_eq!(
                    x25519_base(&k),
                    x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES)
                );
            }
        }
    }
}
