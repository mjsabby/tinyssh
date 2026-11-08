//! Interoperability with the system's OpenSSH client. Each test starts a
//! tinyssh server in-process and runs `ssh` against it; the tests are skipped
//! (with a note) when `ssh`/`ssh-keygen` are not installed.

mod common;

use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tinyssh::{AuthorizedKeys, Config, HostKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;

struct Fixture {
    dir: PathBuf,
    port: u16,
    warn_option: bool,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Starts a server that accepts `id` (and not `other`).
async fn start(adjust: impl FnOnce(&mut Config)) -> Option<Fixture> {
    if !common::have_openssh() {
        eprintln!("skipping: OpenSSH client tools not installed");
        return None;
    }
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "tinyssh-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let id = common::keygen(&dir.join("id"));
    common::keygen(&dir.join("other"));
    let mut config = Config::new(HostKey::generate().unwrap(), AuthorizedKeys::from(vec![id]));
    #[cfg(target_os = "linux")]
    {
        config.shell = Some("/bin/sh".into());
    }
    adjust(&mut config);
    let config: &'static Config = Box::leak(Box::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tinyssh::serve(listener, config));
    let warn_option = std::process::Command::new("ssh")
        .args(["-G", "-o", "WarnWeakCrypto=no", "localhost"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    Some(Fixture {
        dir,
        port,
        warn_option,
    })
}

impl Fixture {
    fn ssh(&self, key: &str, args: &[&str]) -> Command {
        let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut cmd = Command::new("ssh");
        cmd.env_remove("SSH_AUTH_SOCK")
            .args(["-F", null, "-p", &self.port.to_string(), "-i"])
            .arg(self.dir.join(key))
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                &format!("UserKnownHostsFile={null}"),
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=10",
            ]);
        if self.warn_option {
            // curve25519-sha256 is not post-quantum; OpenSSH 10.1+ says so.
            cmd.args(["-o", "WarnWeakCrypto=no"]);
        }
        cmd.args(args).kill_on_drop(true);
        cmd
    }

    async fn run(&self, key: &str, args: &[&str]) -> Output {
        let output = self.ssh(key, args).output();
        tokio::time::timeout(Duration::from_secs(60), output)
            .await
            .expect("ssh timed out")
            .unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_reports_stdout_stderr_and_exit_status() {
    let Some(fx) = start(|_| {}).await else {
        return;
    };
    let (command, newline) = if cfg!(windows) {
        ("echo out&1>&2 echo err&exit /b 7", "\r\n")
    } else {
        ("echo out; echo err >&2; exit 7", "\n")
    };
    let out = fx.run("id", &["tester@127.0.0.1", command]).await;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("out{newline}"),
        "{out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!("err{newline}")),
        "{out:?}"
    );
    assert_eq!(out.status.code(), Some(7));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_key_is_rejected() {
    let Some(fx) = start(|_| {}).await else {
        return;
    };
    let out = fx.run("other", &["tester@127.0.0.1", "true"]).await;
    assert_eq!(out.status.code(), Some(255));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Permission denied (publickey)"),
        "{out:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_round_trip_with_rekeys_from_both_sides() {
    // Server rekeys every 512 KiB, the client every 1 MiB.
    let Some(fx) = start(|c| c.rekey_limit = 512 * 1024).await else {
        return;
    };
    let input: Vec<u8> = (0..12 << 20)
        .map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let command = if cfg!(windows) {
        r#"powershell.exe -NoLogo -NoProfile -NonInteractive -Command "[Console]::OpenStandardInput().CopyTo([Console]::OpenStandardOutput())""#
    } else {
        "cat"
    };
    let mut child = fx
        .ssh("id", &["-o", "RekeyLimit=1M", "tester@127.0.0.1", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = input.clone();
    let writer = tokio::spawn(async move {
        stdin.write_all(&data).await.unwrap();
        // Dropping stdin sends EOF to the remote process.
    });
    let mut echoed = Vec::new();
    let mut stdout = child.stdout.take().unwrap();
    let read = stdout.read_to_end(&mut echoed);
    tokio::time::timeout(Duration::from_secs(120), read)
        .await
        .expect("timed out")
        .unwrap();
    writer.await.unwrap();
    let status = child.wait().await.unwrap();
    assert_eq!(echoed.len(), input.len());
    assert!(echoed == input, "echoed data differs");
    assert_eq!(status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn large_output_survives_server_rekeys() {
    let Some(fx) = start(|c| c.rekey_limit = 1 << 20).await else {
        return;
    };
    let command = if cfg!(windows) {
        r#"powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$o = [Console]::OpenStandardOutput(); $b = New-Object byte[] 1000000; for ($i = 0; $i -lt 40; $i++) { $o.Write($b, 0, $b.Length) }; [Console]::Error.WriteLine('done')""#
    } else {
        "head -c 40000000 /dev/zero; echo done >&2"
    };
    let out = fx.run("id", &["tester@127.0.0.1", command]).await;
    assert_eq!(
        out.stdout.len(),
        40_000_000,
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.iter().all(|&b| b == 0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("done"));
    assert_eq!(out.status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn interactive_pty_session() {
    let Some(fx) = start(|_| {}).await else {
        return;
    };
    let mut child = fx
        .ssh("id", &["-tt", "tester@127.0.0.1"])
        .env("TERM", "xterm-256color")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let command: &[u8] = if cfg!(windows) {
        b"echo TINYSSH-%OS%&exit 5\r\n"
    } else {
        b"tty | sed 's/^/TTY=/'; echo \"TERM=$TERM\"; exit 5\n"
    };
    stdin.write_all(command).await.unwrap();
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("timed out")
        .unwrap();
    drop(stdin);
    let text = String::from_utf8_lossy(&out.stdout);
    if cfg!(windows) {
        assert!(text.contains("TINYSSH-Windows_NT"), "{out:?}");
        assert!(text.contains("\x1b["), "{out:?}");
    } else {
        assert!(text.contains("TTY=/dev/pts/"), "{out:?}");
        assert!(text.contains("TERM=xterm-256color"), "{out:?}");
    }
    assert_eq!(out.status.code(), Some(5), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_shell_is_reported() {
    let Some(fx) = start(|c| c.shell = Some("/nonexistent/shell".into())).await else {
        return;
    };
    let out = fx.run("id", &["tester@127.0.0.1", "true"]).await;
    assert_eq!(out.status.code(), Some(127));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot start session"),
        "{out:?}"
    );
}
