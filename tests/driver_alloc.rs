//! The tokio driver performs no heap allocation in steady state. Allocations
//! are counted on every thread but the test's own (the client side): the
//! server's runtime thread and any thread that reports I/O completions to it.
//! Meanwhile the OpenSSH client pumps data through a binary echo process in
//! both directions, with rekeys initiated by both sides. Skipped when OpenSSH
//! is not installed.
#![cfg(debug_assertions)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tinyssh::{AuthorizedKeys, Config, HostKey};

struct Counting;

static MEASURING: AtomicBool = AtomicBool::new(false);
/// Allocations outside the client while measuring, and in total.
static COUNT: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Set on the test's own threads, whose allocations are not counted.
    static CLIENT: Cell<bool> = const { Cell::new(false) };
}

fn note() {
    if !CLIENT.try_with(Cell::get).unwrap_or(false) {
        TOTAL.fetch_add(1, Ordering::Relaxed);
        if MEASURING.load(Ordering::Relaxed) {
            COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// SAFETY: forwards to the system allocator.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        note();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn driver_steady_state_does_not_allocate() {
    CLIENT.set(true);
    if !common::have_openssh() {
        eprintln!("skipping: OpenSSH client tools not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("tinyssh-alloc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("id");
    let id = common::keygen(&key);

    let mut config = Config::new(HostKey::generate().unwrap(), AuthorizedKeys::from(vec![id]));
    #[cfg(target_os = "linux")]
    {
        config.shell = Some("/bin/sh".into());
    }
    config.rekey_limit = 4 << 20;
    let config: &'static Config = Box::leak(Box::new(config));
    let (port_tx, port_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            port_tx.send(listener.local_addr().unwrap().port()).unwrap();
            tinyssh::serve(listener, config).await
        })
    });
    let port = port_rx.recv().unwrap();

    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    // On Windows the echo pauses after each MiB, so that writes to it have to
    // wait for the thread pool's completion callbacks.
    let command = if cfg!(windows) {
        r#"powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$i = [Console]::OpenStandardInput(); $o = [Console]::OpenStandardOutput(); $b = [byte[]]::new(65536); $t = 0; while (($n = $i.Read($b, 0, $b.Length)) -gt 0) { $o.Write($b, 0, $n); $t += $n; if ($t -ge 1MB) { $t = 0; Start-Sleep -Milliseconds 50 } }""#
    } else {
        "cat"
    };
    let at_connect = TOTAL.load(Ordering::SeqCst);
    let mut child = Command::new("ssh")
        .env_remove("SSH_AUTH_SOCK")
        .args(["-F", null, "-p", &port.to_string(), "-i"])
        .arg(&key)
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
        ])
        .args([
            "-o",
            &format!("UserKnownHostsFile={null}"),
            "-o",
            "LogLevel=QUIET",
            "-o",
            "RekeyLimit=8M",
        ])
        .args(["tester@127.0.0.1", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        CLIENT.set(true);
        let block = [0x5au8; 64 * 1024];
        // Runs until the session is torn down.
        while stdin.write_all(&block).is_ok() {}
    });

    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let mut echoed = 0u64;
    let (warm_up, measured) = (16u64 << 20, 64u64 << 20);
    while echoed < warm_up + measured {
        if echoed >= warm_up {
            MEASURING.store(true, Ordering::SeqCst);
        }
        let n = stdout.read(&mut buf).unwrap();
        assert!(n > 0, "session ended early");
        assert!(buf[..n].iter().all(|&b| b == 0x5a));
        echoed += n as u64;
    }
    MEASURING.store(false, Ordering::SeqCst);
    let _ = child.kill();
    let _ = child.wait();
    let _ = writer.join();
    let _ = std::fs::remove_dir_all(&dir);
    // Positive control: the server's setup (arena, process spawn, key
    // exchange) allocated outside the client, so the counter does see it.
    assert!(TOTAL.load(Ordering::SeqCst) > at_connect);
    assert_eq!(
        COUNT.load(Ordering::SeqCst),
        0,
        "the server allocated in steady state"
    );
}
