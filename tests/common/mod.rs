//! Helpers for the integration tests that drive the OpenSSH client.

use std::path::Path;
use std::process::{Command, Stdio};
use tinyssh::PublicKey;

/// Whether `ssh` and `ssh-keygen` are installed.
pub fn have_openssh() -> bool {
    ["ssh", "ssh-keygen"].iter().all(|tool| {
        Command::new(tool)
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    })
}

/// Creates an Ed25519 key pair with `ssh-keygen` (`path` becomes the private
/// key file for `ssh -i`) and returns its public key.
pub fn keygen(path: &Path) -> PublicKey {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(status.success());
    // "ssh-ed25519 <base64 blob> <comment>", where the blob is
    // string("ssh-ed25519") || string(32-byte key).
    let line = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    let blob = base64_decode(line.split_whitespace().nth(1).expect("key blob"));
    let (prefix, key) = blob.split_at(blob.len() - 32);
    assert_eq!(prefix, b"\0\0\0\x0bssh-ed25519\0\0\0\x20");
    PublicKey::from_bytes(key.try_into().unwrap())
}

fn base64_decode(text: &str) -> Vec<u8> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 character {c:#x}"),
        };
        // Bits shifted out at the top were already emitted.
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
