//! A tiny standalone server built on tinyssh.
//!
//! ```text
//! tinysshd --authorized-keys PATH [--listen ADDR] [--host-key PATH] [--shell PATH]
//! ```
//!
//! Keys are stored as hex. The host key file holds the 32-byte Ed25519 seed
//! and is generated on first start. The authorized keys file holds one 32-byte
//! public key per line (`#` starts a comment line); for an OpenSSH key, that
//! is the last 32 bytes of the base64 blob in its `.pub` file:
//!
//! ```text
//! cut -d' ' -f2 ~/.ssh/id_ed25519.pub | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n'
//! ```

use std::error::Error;
use std::path::{Path, PathBuf};
use tinyssh::{AuthorizedKeys, Config, HostKey, PublicKey};

const USAGE: &str =
    "usage: tinysshd --authorized-keys PATH [--listen ADDR] [--host-key PATH] [--shell PATH]";

fn main() -> Result<(), Box<dyn Error>> {
    let mut listen = String::from("0.0.0.0:2222");
    let mut host_key = PathBuf::from("tinyssh_host_key");
    let mut authorized = None;
    let mut shell = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--listen" => listen = value()?,
            "--host-key" => host_key = value()?.into(),
            "--authorized-keys" => authorized = Some(PathBuf::from(value()?)),
            "--shell" => shell = Some(value()?),
            _ => return Err(format!("unknown argument {flag}\n{USAGE}").into()),
        }
    }
    let authorized = authorized.ok_or(USAGE)?;

    let key = match std::fs::read_to_string(&host_key) {
        Ok(text) => HostKey::from_seed(&parse_hex(&text).ok_or_else(|| bad_key(&host_key, 1))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = HostKey::generate()?;
            write_private(&host_key, &format!("{}\n", hex(&key.to_seed())))?;
            eprintln!("generated host key {}", host_key.display());
            key
        }
        Err(e) => return Err(e.into()),
    };
    let mut keys = AuthorizedKeys::default();
    for (n, line) in std::fs::read_to_string(&authorized)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = parse_hex(line).ok_or_else(|| bad_key(&authorized, n + 1))?;
        keys.push(PublicKey::from_bytes(bytes));
    }
    if keys.keys().is_empty() {
        return Err(format!("no keys in {}", authorized.display()).into());
    }

    let mut config = Config::new(key, keys);
    config.shell = shell;
    let config: &'static Config = Box::leak(Box::new(config));
    eprintln!(
        "host public key {}",
        hex(config.host_key.public_key().as_bytes())
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        eprintln!("listening on {}", listener.local_addr()?);
        tinyssh::serve(listener, config).await
    })
}

fn bad_key(path: &Path, line: usize) -> String {
    format!("{}:{line}: expected 64 hex digits", path.display())
}

/// Parses exactly 32 bytes written as 64 hex digits.
fn parse_hex(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(path)?, contents.as_bytes())
}
