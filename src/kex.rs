//! `curve25519-sha256` key exchange (RFC 8731), algorithm negotiation and
//! key derivation (RFC 4253 §7).

use crate::Error;
use crate::cipher::Aead;
use crate::sha256::Sha256;
use crate::wire::{Count, Hash, Msg, Overflow, Put, Res, first_name, has_name, msg};
use crate::{curve25519, rng};

pub(crate) const KEX: &[u8] = b"curve25519-sha256";
pub(crate) const HOST_KEY_ALG: &[u8] = b"ssh-ed25519";
pub(crate) const CIPHER: &[u8] = b"aes128-gcm@openssh.com";
const COMPRESSION: &[u8] = b"none";
// OpenSSH strict KEX (Terrapin mitigation) markers; only valid in the first
// KEXINIT of a connection.
const STRICT_SERVER: &[u8] = b"kex-strict-s-v00@openssh.com";
const STRICT_CLIENT: &[u8] = b"kex-strict-c-v00@openssh.com";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Server,
    #[cfg_attr(not(test), allow(dead_code))]
    Client,
}

/// Writes a KEXINIT payload that advertises exactly one suite.
pub(crate) fn write_kexinit(w: &mut impl Put, cookie: &[u8; 16], role: Role, initial: bool) -> Res {
    w.put_u8(msg::KEXINIT)?;
    w.put_raw(cookie)?;
    let marker = match role {
        Role::Server => STRICT_SERVER,
        Role::Client => STRICT_CLIENT,
    };
    match initial {
        true => {
            let len = KEX.len().saturating_add(1).saturating_add(marker.len());
            w.put_u32(u32::try_from(len).unwrap_or_default())?;
            w.put_raw(KEX)?;
            w.put_raw(b",")?;
            w.put_raw(marker)?;
        }
        false => w.put_string(KEX)?,
    }
    w.put_string(HOST_KEY_ALG)?;
    w.put_string(CIPHER)?;
    w.put_string(CIPHER)?;
    // An AEAD cipher carries its own MAC; OpenSSH, PuTTY and Go all skip MAC
    // negotiation for it, so no MAC is advertised.
    w.put_string(b"")?;
    w.put_string(b"")?;
    w.put_string(COMPRESSION)?;
    w.put_string(COMPRESSION)?;
    w.put_string(b"")?;
    w.put_string(b"")?;
    w.put_bool(false)?;
    w.put_u32(0)
}

/// Writes `string(KEXINIT payload)` without materializing the payload.
pub(crate) fn put_kexinit_string(
    w: &mut impl Put,
    cookie: &[u8; 16],
    role: Role,
    initial: bool,
) -> Res {
    let mut len = Count(0);
    write_kexinit(&mut len, cookie, role, initial)?;
    w.put_u32(u32::try_from(len.0).map_err(|_| Overflow)?)?;
    write_kexinit(w, cookie, role, initial)
}

/// What the peer's KEXINIT implies beyond the (fixed) algorithms.
pub(crate) struct PeerKexInit {
    /// Both sides support strict KEX (only set for the initial exchange).
    pub(crate) strict: bool,
    /// The peer sent a guessed KEX packet that must be ignored.
    pub(crate) wrong_guess: bool,
}

/// Checks that the peer's KEXINIT accepts our single suite.
pub(crate) fn negotiate(payload: &[u8], role: Role, initial: bool) -> Result<PeerKexInit, Error> {
    let mut m = Msg::new(payload);
    m.u8()?;
    m.bytes::<16>()?;
    let kex = m.string()?;
    let host_key = m.string()?;
    let cipher_cs = m.string()?;
    let cipher_sc = m.string()?;
    let _mac_cs = m.string()?;
    let _mac_sc = m.string()?;
    let comp_cs = m.string()?;
    let comp_sc = m.string()?;
    let _lang_cs = m.string()?;
    let _lang_sc = m.string()?;
    let follows = m.bool()?;
    m.u32()?;
    if !has_name(kex, KEX) {
        return Err(Error::Protocol(
            "no common key exchange (need curve25519-sha256)",
        ));
    }
    if !has_name(host_key, HOST_KEY_ALG) {
        return Err(Error::Protocol(
            "no common host key algorithm (need ssh-ed25519)",
        ));
    }
    if !has_name(cipher_cs, CIPHER) || !has_name(cipher_sc, CIPHER) {
        return Err(Error::Protocol(
            "no common cipher (need aes128-gcm@openssh.com)",
        ));
    }
    if !has_name(comp_cs, COMPRESSION) || !has_name(comp_sc, COMPRESSION) {
        return Err(Error::Protocol("no common compression (need none)"));
    }
    let marker = match role {
        Role::Server => STRICT_CLIENT,
        Role::Client => STRICT_SERVER,
    };
    Ok(PeerKexInit {
        strict: initial && has_name(kex, marker),
        // RFC 4253 §7: a guess is right only if both preferred algorithms match.
        wrong_guess: follows && (first_name(kex) != KEX || first_name(host_key) != HOST_KEY_ALG),
    })
}

/// Completes the exchange hash H with `Q_C`, `Q_S` and `K`.
pub(crate) fn finish_hash(
    mut h: Sha256,
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    k: &Secret,
) -> Result<[u8; 32], Error> {
    let res: Res = (|| {
        let mut w = Hash(&mut h);
        w.put_string(q_c)?;
        w.put_string(q_s)?;
        w.put_mpint(&k.0)
    })();
    res.map_err(|_| Error::Protocol("exchange hash"))?;
    Ok(h.finalize())
}

/// An ephemeral X25519 secret key, wiped on drop.
pub(crate) struct Ephemeral([u8; 32]);

impl Ephemeral {
    /// The server's side of the exchange: a fresh key pair's public value,
    /// and the shared secret with the client's `peer`, rejecting low-order
    /// peer points (RFC 8731 §3: an all-zero result MUST abort the exchange).
    pub(crate) fn exchange(peer: &[u8; 32]) -> Result<([u8; 32], Secret), Error> {
        let secret = Self(rng::array::<32>()?);
        let (public, shared) = curve25519::x25519_pair(&secret.0, peer)
            .ok_or(Error::Protocol("invalid curve25519 public key"))?;
        Ok((public, Secret(shared)))
    }

    /// Generates a key pair and returns it with its public value (the
    /// client's side, which sends its public value first).
    #[cfg(test)]
    pub(crate) fn generate() -> Result<(Self, [u8; 32]), Error> {
        let secret = Self(rng::array::<32>()?);
        let public = curve25519::x25519_base(&secret.0);
        Ok((secret, public))
    }

    /// Computes the shared secret, rejecting low-order peer points.
    #[cfg(test)]
    pub(crate) fn agree(self, peer: &[u8; 32]) -> Result<Secret, Error> {
        curve25519::x25519(&self.0, peer)
            .map(Secret)
            .ok_or(Error::Protocol("invalid curve25519 public key"))
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        rng::wipe(&mut self.0);
    }
}

/// The shared secret `K`, wiped on drop.
pub(crate) struct Secret(pub(crate) [u8; 32]);

impl Drop for Secret {
    fn drop(&mut self) {
        rng::wipe(&mut self.0);
    }
}

/// `HASH(K || H || letter || session_id)` (RFC 4253 §7.2).
fn derive(k: &Secret, h: &[u8; 32], letter: u8, session_id: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut d = Sha256::new();
    Hash(&mut d)
        .put_mpint(&k.0)
        .map_err(|_| Error::Protocol("key derivation"))?;
    d.update(h);
    d.update(&[letter]);
    d.update(session_id);
    Ok(d.finalize())
}

/// Derives the (client-to-server, server-to-client) packet protection.
pub(crate) fn derive_keys(
    k: &Secret,
    h: &[u8; 32],
    session_id: &[u8; 32],
) -> Result<(Aead, Aead), Error> {
    let mut iv_cs = derive(k, h, b'A', session_id)?;
    let mut iv_sc = derive(k, h, b'B', session_id)?;
    let mut key_cs = derive(k, h, b'C', session_id)?;
    let mut key_sc = derive(k, h, b'D', session_id)?;
    let keys = match (
        key_cs.first_chunk::<16>(),
        iv_cs.first_chunk::<12>(),
        key_sc.first_chunk::<16>(),
        iv_sc.first_chunk::<12>(),
    ) {
        (Some(kc), Some(ic), Some(ks), Some(is)) => Ok((Aead::new(kc, *ic), Aead::new(ks, *is))),
        _ => Err(Error::Protocol("key derivation")),
    };
    for secret in [&mut iv_cs, &mut iv_sc, &mut key_cs, &mut key_sc] {
        rng::wipe(secret);
    }
    keys
}
