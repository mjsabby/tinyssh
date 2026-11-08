//! Ed25519 host keys, user public keys and authorization policy.
//!
//! Keys are raw 32-byte Ed25519 values; storing and parsing them is up to the
//! program embedding tinyssh.

use crate::curve25519::ed25519::{self, SigningKey};
use crate::kex::HOST_KEY_ALG;
use crate::wire::{Buf, Msg, Put};
use crate::{Error, rng};
use std::fmt;

/// Length of the SSH encoding of an Ed25519 public key.
const BLOB_LEN: usize = 4 + 11 + 4 + 32;
/// Length of the SSH encoding of an Ed25519 signature.
pub(crate) const SIG_BLOB_LEN: usize = 4 + 11 + 4 + 64;

/// An `ssh-ed25519` public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wraps raw Ed25519 public key bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw Ed25519 public key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// SSH wire encoding: `string "ssh-ed25519" || string key`.
    pub(crate) fn blob(&self) -> [u8; BLOB_LEN] {
        let mut out = [0; BLOB_LEN];
        let mut w = Buf::new(&mut out);
        // Cannot fail: the buffer is exactly the encoded size.
        let _ = w
            .put_string(HOST_KEY_ALG)
            .and_then(|()| w.put_string(&self.0));
        out
    }

    /// Parses the SSH wire encoding of an `ssh-ed25519` key.
    pub(crate) fn from_blob(blob: &[u8]) -> Option<Self> {
        let mut m = Msg::new(blob);
        (m.string().ok()? == HOST_KEY_ALG).then_some(())?;
        let key = m.fixed_string::<32>().ok()?;
        m.end().ok()?;
        Some(Self(key))
    }

    /// Verifies an SSH signature blob over the concatenation of `parts`.
    /// Keys of small order are rejected.
    pub(crate) fn verify(&self, parts: &[&[u8]], sig_blob: &[u8]) -> bool {
        let mut m = Msg::new(sig_blob);
        match (m.string(), m.fixed_string::<64>(), m.end()) {
            (Ok(alg), Ok(sig), Ok(())) if alg == HOST_KEY_ALG => {
                ed25519::verify(&self.0, parts, &sig)
            }
            _ => false,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PublicKey(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

/// The server's `ssh-ed25519` host key.
pub struct HostKey {
    key: SigningKey,
}

impl HostKey {
    /// Creates a host key from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_seed(seed),
        }
    }

    /// Generates a fresh host key from OS randomness.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = rng::array::<32>()?;
        let key = Self::from_seed(&seed);
        rng::wipe(&mut seed);
        Ok(key)
    }

    /// The 32-byte Ed25519 seed, for storing a generated key. It is the
    /// private key: keep it secret.
    pub fn to_seed(&self) -> [u8; 32] {
        self.key.seed()
    }

    /// The public half of the host key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.key.public())
    }

    /// Signs `data`, returning the SSH signature blob.
    pub(crate) fn sign(&self, data: &[u8]) -> [u8; SIG_BLOB_LEN] {
        let mut out = [0; SIG_BLOB_LEN];
        let mut w = Buf::new(&mut out);
        // Cannot fail: the buffer is exactly the encoded size.
        let _ = w
            .put_string(HOST_KEY_ALG)
            .and_then(|()| w.put_string(&self.key.sign(data)));
        out
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostKey({:?})", self.public_key())
    }
}

/// Decides whether a user may log in with a public key.
///
/// Called for every `publickey` authentication attempt (also for the
/// signature-less queries clients send first), so it should be cheap.
pub trait Authorizer: Send + Sync {
    /// Returns `true` if `user` may authenticate with `key`.
    fn authorize(&self, user: &str, key: &PublicKey) -> bool;
}

impl<F: Fn(&str, &PublicKey) -> bool + Send + Sync> Authorizer for F {
    fn authorize(&self, user: &str, key: &PublicKey) -> bool {
        self(user, key)
    }
}

/// A list of keys allowed to log in as any user.
#[derive(Clone, Debug, Default)]
pub struct AuthorizedKeys {
    keys: Vec<PublicKey>,
}

impl AuthorizedKeys {
    /// Adds a key.
    pub fn push(&mut self, key: PublicKey) {
        self.keys.push(key);
    }

    /// The accepted keys.
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }
}

impl From<Vec<PublicKey>> for AuthorizedKeys {
    fn from(keys: Vec<PublicKey>) -> Self {
        Self { keys }
    }
}

impl Authorizer for AuthorizedKeys {
    fn authorize(&self, _user: &str, key: &PublicKey) -> bool {
        self.keys.contains(key)
    }
}
