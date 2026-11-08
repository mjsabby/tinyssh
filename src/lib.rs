//! # tinyssh
//!
//! A deliberately small SSHv2 **server** library for interactive shell access,
//! meant to be embedded (for example in a Linux distribution's init) rather
//! than configured. It implements a minimal subset of RFC 4253 (transport),
//! RFC 4252 (user authentication) and RFC 4254 (connection) with exactly one
//! cryptographic suite:
//!
//! | Purpose            | Algorithm                                  |
//! |--------------------|--------------------------------------------|
//! | Key exchange       | `curve25519-sha256` (+ OpenSSH strict KEX) |
//! | Host / user keys   | `ssh-ed25519`                              |
//! | Cipher + MAC       | `aes128-gcm@openssh.com`                   |
//! | Compression        | `none`                                     |
//!
//! Only `publickey` authentication and a single `session` channel at a time
//! are supported (`pty-req`, `shell`, `exec` and `window-change` requests,
//! `exit-status` reporting). Both peer- and self-initiated rekeying are
//! supported. There is no password authentication, no port forwarding and no
//! channel multiplexing.
//!
//! ## Requirements
//!
//! x86-64 with AVX2, BMI2, ADX, AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ and SHA-NI
//! (AMD Zen 3 and later, Intel Ice Lake and later). The cryptography is
//! written for these instructions, and tinyssh is compiled for them instead
//! of checking the CPU at run time: the crate does not build unless they are
//! enabled, for example with
//! `RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq,+vaes,+vpclmulqdq,+sha,+adx"`
//! (this repository's `.cargo/config.toml` sets them). Programs that depend on
//! tinyssh need the same flags.
//!
//! ## Design
//!
//! * **Sans-IO core.** [`Connection`] is a pure state machine: feed it socket
//!   bytes, take bytes to send, and react to [`Event`]s. [`serve`] and
//!   [`serve_connection`] drive it with tokio and a pseudo-terminal (Linux
//!   `/dev/ptmx`, Windows ConPTY) or pipes.
//! * **Arena allocation.** Every buffer a connection needs lives in one
//!   [`Arena`] allocated when the connection is accepted. Once a session is
//!   running, the protocol core, the tokio driver and rekeying perform no heap
//!   allocation (enforced by the allocation tests).
//! * **Panic-free.** The library is built with clippy lints that forbid
//!   indexing, unchecked arithmetic, `unwrap`/`expect` and explicit panics;
//!   malformed input surfaces as an [`Error`] and a `SSH_MSG_DISCONNECT`.
//! * **Simple ownership.** No `Arc`, `Rc`, `RefCell` or locks: one task per
//!   connection owns all of its state, and the shared [`Config`] is borrowed.
//!
//! ## Example
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! # let (seed, admin_key) = ([0u8; 32], [0u8; 32]);
//! // Keys are raw Ed25519 bytes; how they are stored is up to the caller.
//! let host_key = tinyssh::HostKey::from_seed(&seed);
//! let keys = tinyssh::AuthorizedKeys::from(vec![tinyssh::PublicKey::from_bytes(admin_key)]);
//! // The config is shared by every connection task for the life of the process.
//! let config: &'static tinyssh::Config = Box::leak(Box::new(tinyssh::Config::new(host_key, keys)));
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:22").await?;
//! tinyssh::serve(listener, config).await // never returns
//! # }
//! ```
#![deny(missing_docs, unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    deny(
        clippy::arithmetic_side_effects,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::unwrap_used
    )
)]

// Every `unsafe` call into a `#[target_feature]` function or assembly using
// these instructions relies on this: the features are enabled for the whole
// build, so the CPU is required to have them anyway. (Rustdoc does not get the
// build's target features, and documentation runs no code.)
#[cfg(not(any(
    doc,
    all(
        target_arch = "x86_64",
        target_feature = "avx2",
        target_feature = "bmi2",
        target_feature = "adx",
        target_feature = "aes",
        target_feature = "pclmulqdq",
        target_feature = "vaes",
        target_feature = "vpclmulqdq",
        target_feature = "sha",
    )
)))]
compile_error!(
    "tinyssh must be compiled for x86-64 with AVX2, BMI2, ADX, AES-NI, PCLMULQDQ, VAES, \
     VPCLMULQDQ and SHA-NI: set RUSTFLAGS=\"-C target-cpu=x86-64-v3 \
     -C target-feature=+aes,+pclmulqdq,+vaes,+vpclmulqdq,+sha,+adx\" (see .cargo/config.toml)"
);

mod cipher;
mod conn;
mod curve25519;
mod kex;
mod keys;
#[cfg(target_os = "linux")]
mod launch;
mod rng;
mod server;
mod sha256;
mod sha512;
mod sys;
mod transport;
mod wire;

#[cfg(test)]
mod tests;

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub use conn::{Arena, Connection, Event, Memory, Pty, SpawnRequest, WinSize};
pub use keys::{AuthorizedKeys, Authorizer, HostKey, PublicKey};
#[cfg(target_os = "linux")]
pub use launch::{Launch, Launcher};
pub use server::{serve, serve_connection};

/// Identification string sent to clients (RFC 4253 §4.2), without CR LF.
pub const VERSION: &str = "SSH-2.0-tinyssh_1.0";

/// Server configuration shared (by reference) between all connections.
pub struct Config {
    /// The server's `ssh-ed25519` host key.
    pub host_key: HostKey,
    /// Decides which user/key pairs may log in.
    pub authorizer: Box<dyn Authorizer>,
    /// Program to run instead of the account's login shell. `exec` requests
    /// run `<shell> -c <command>` (on Windows with the command quoted as one
    /// argument), except with `cmd.exe` (the default on Windows, from
    /// `%COMSPEC%`): `cmd.exe /s /c "<command>"`. Not used with a
    /// `launcher` (Linux).
    pub shell: Option<String>,
    /// Starts session processes the embedding program's way, in place of
    /// the account lookup, login shell and environment described under
    /// [`shell`](Self::shell). Linux only; `None` by default.
    #[cfg(target_os = "linux")]
    pub launcher: Option<Box<dyn Launcher>>,
    /// Start a key re-exchange after this many bytes in either direction.
    /// Defaults to 4 GiB.
    pub rekey_limit: u64,
    /// Receive window (and stdin buffer) per session in bytes; a window
    /// adjustment is sent whenever half of it has been consumed. Defaults to
    /// 2 MiB.
    pub window_size: u32,
    /// Failed authentication attempts tolerated before disconnecting.
    pub max_auth_attempts: u32,
    /// Time a client has to authenticate.
    pub login_timeout: Duration,
    /// Maximum number of simultaneous connections accepted by [`serve`];
    /// further connections are closed immediately.
    pub max_connections: usize,
    active: AtomicUsize,
}

impl Config {
    /// Creates a configuration with the default limits.
    pub fn new(host_key: HostKey, authorizer: impl Authorizer + 'static) -> Self {
        Self {
            host_key,
            authorizer: Box::new(authorizer),
            shell: None,
            #[cfg(target_os = "linux")]
            launcher: None,
            rekey_limit: 1 << 32,
            window_size: 2 * 1024 * 1024,
            max_auth_attempts: 6,
            login_timeout: Duration::from_secs(60),
            max_connections: 16,
            active: AtomicUsize::new(0),
        }
    }

    /// Reserves a connection slot; `None` when `max_connections` are active.
    fn admit(&self) -> Option<Admission<'_>> {
        let slot = Admission(&self.active);
        let previous = self.active.fetch_add(1, Ordering::AcqRel);
        (previous < self.max_connections).then_some(slot)
    }
}

/// A reserved connection slot, released when dropped.
struct Admission<'a>(&'a AtomicUsize);

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Errors produced by tinyssh.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Socket, process or randomness I/O failed.
    Io(std::io::Error),
    /// The peer violated the protocol or no common algorithm exists.
    Protocol(&'static str),
    /// A packet failed AES-GCM authentication.
    Mac,
    /// The peer disconnected (`SSH_MSG_DISCONNECT` or end of stream).
    Disconnected,
    /// The client did not authenticate within [`Config::login_timeout`].
    Timeout,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(what) => write!(f, "protocol error: {what}"),
            Self::Mac => f.write_str("packet authentication failed"),
            Self::Disconnected => f.write_str("peer disconnected"),
            Self::Timeout => f.write_str("login timeout"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
