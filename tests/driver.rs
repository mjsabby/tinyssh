//! Driver limits that need no SSH client: login timeout and connection cap.

use std::time::Duration;
use tinyssh::{AuthorizedKeys, Config, Error, HostKey};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

fn config(adjust: impl FnOnce(&mut Config)) -> &'static Config {
    let mut config = Config::new(HostKey::generate().unwrap(), AuthorizedKeys::default());
    adjust(&mut config);
    Box::leak(Box::new(config))
}

/// Reads until the server closes the connection; returns what it sent.
async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let read = stream.read_to_end(&mut out);
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("server kept the connection")
        .unwrap();
    out
}

#[tokio::test]
async fn idle_clients_are_dropped_after_the_login_timeout() {
    let config = config(|c| c.login_timeout = Duration::from_millis(200));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let served = tokio::spawn(tinyssh::serve_connection(server, config));
    let sent = read_all(&mut client).await;
    assert!(sent.starts_with(b"SSH-2.0-tinyssh_1.0\r\n"));
    assert!(matches!(served.await.unwrap(), Err(Error::Timeout)));
}

/// A client that keeps the server busy before authenticating (IGNORE
/// packets, as fast as a thread can send them) is still dropped at the login
/// timeout, even on a current-thread runtime.
#[test]
fn busy_clients_are_dropped_after_the_login_timeout() {
    use std::io::Write;
    let config = config(|c| c.login_timeout = Duration::from_millis(100));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let flood = std::thread::spawn(move || {
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        // Unencrypted: length 12, padding length 6, IGNORE with an empty
        // string, six bytes of padding.
        let packet = [0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let burst: Vec<u8> = packet.iter().copied().cycle().take(16 * 4096).collect();
        client.write_all(b"SSH-2.0-flood\r\n").unwrap();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) && client.write_all(&burst).is_ok() {}
    });
    let (server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (result, elapsed) = runtime.block_on(async {
        let server = TcpStream::from_std(server).unwrap();
        let start = std::time::Instant::now();
        let result = tinyssh::serve_connection(server, config).await;
        (result, start.elapsed())
    });
    assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "timed out after {elapsed:?}"
    );
    flood.join().unwrap();
}

#[tokio::test]
async fn garbage_is_refused() {
    let config = config(|_| {});
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let served = tokio::spawn(tinyssh::serve_connection(server, config));
    tokio::io::AsyncWriteExt::write_all(&mut client, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    read_all(&mut client).await;
    assert!(matches!(served.await.unwrap(), Err(Error::Protocol(_))));
}

#[tokio::test]
async fn connections_beyond_the_limit_are_closed() {
    let config = config(|c| c.max_connections = 1);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(tinyssh::serve(listener, config));

    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut banner = [0u8; 8];
    first.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
    // The single slot is taken: the next client is turned away at once.
    let mut second = TcpStream::connect(addr).await.unwrap();
    assert!(read_all(&mut second).await.is_empty());
    // Once the first client leaves, the slot is free again.
    drop(first);
    for _ in 0..50 {
        let mut third = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), third.read(&mut byte))
            .await
            .unwrap();
        if read.unwrap() == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("slot was never released");
}
