//! In-crate tests: an in-memory client drives the sans-IO server through
//! complete sessions, rekeys, failures and an allocation check.

#[cfg(debug_assertions)]
mod alloc;
mod client;

use crate::wire::{Put, msg, reason};
use crate::{Arena, AuthorizedKeys, Config, Connection, Error, Event, HostKey, WinSize};
use client::{Client, KexStyle, pattern};

/// A small deterministic generator (xorshift64*) for test inputs.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub(crate) fn u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0; N];
        for chunk in out.chunks_mut(8) {
            let len = chunk.len();
            chunk.copy_from_slice(&self.u64().to_le_bytes()[..len]);
        }
        out
    }
}

/// The fake session process: echoes stdin to stdout, like `cat`.
#[derive(Default)]
struct App {
    spawned: u32,
    command: Option<Vec<u8>>,
    term: Option<String>,
    size: Option<(u16, u16)>,
    resized: Option<(u16, u16)>,
    hangups: u32,
    running: bool,
    /// Exit with this code once stdin is closed and echoed.
    exit_on_eof: Option<u32>,
    /// Write this to stderr and exit right after spawning.
    fail_with: Option<(&'static [u8], u32)>,
}

impl App {
    fn on_event(&mut self, event: Event<'_>) {
        match event {
            Event::Spawn(req) => {
                self.spawned += 1;
                self.running = true;
                self.command = req.command.map(<[u8]>::to_vec);
                self.term = req.pty.map(|p| p.term.to_owned());
                self.size = req.pty.map(|p| (p.size.cols, p.size.rows));
                assert_eq!(req.user, "tester");
            }
            Event::Resize(size) => self.resized = Some((size.cols, size.rows)),
            Event::Hangup => {
                self.hangups += 1;
                self.running = false;
            }
        }
    }

    /// Moves data like a process would; returns whether anything happened.
    fn run(&mut self, server: &mut Connection<'_>, scratch: &mut [u8]) -> Result<bool, Error> {
        if !self.running {
            return Ok(false);
        }
        if let Some((text, code)) = self.fail_with.take() {
            server.output(true, text)?;
            server.exited(code)?;
            self.running = false;
            return Ok(true);
        }
        let mut progress = false;
        loop {
            let n = server
                .stdin()
                .len()
                .min(server.output_room())
                .min(scratch.len());
            if n == 0 {
                break;
            }
            scratch[..n].copy_from_slice(&server.stdin()[..n]);
            server.stdin_consumed(n)?;
            server.output(false, &scratch[..n])?;
            progress = true;
        }
        if server.stdin_closed()
            && let Some(code) = self.exit_on_eof
        {
            server.exited(code)?;
            self.running = false;
            progress = true;
        }
        Ok(progress)
    }
}

struct Harness {
    server: Connection<'static>,
    client: Client<'static>,
    app: App,
    scratch: &'static mut [u8],
}

fn client_key() -> HostKey {
    HostKey::from_seed(&[9; 32])
}

fn new_client(key: HostKey, style: Option<KexStyle>) -> Client<'static> {
    let buffers: &'static mut [u8] = Box::leak(vec![0u8; 256 * 1024].into_boxed_slice());
    let (rx, tx) = buffers.split_at_mut(128 * 1024);
    let mut client = Client::idle(rx, tx, key, "tester");
    client.style = style;
    client
}

fn setup_with(key: HostKey, adjust: impl FnOnce(&mut Config), style: Option<KexStyle>) -> Harness {
    let authorized = client_key().public_key();
    let mut config = Config::new(
        HostKey::from_seed(&[7; 32]),
        AuthorizedKeys::from(vec![authorized]),
    );
    adjust(&mut config);
    let config: &'static Config = Box::leak(Box::new(config));
    let arena: &'static mut Arena = Box::leak(Box::new(Arena::new(config)));
    let (memory, scratch) = arena.split();
    let server = Connection::new(config, memory).unwrap();
    let mut client = new_client(key, style);
    client.start().unwrap();
    Harness {
        server,
        client,
        app: App::default(),
        scratch,
    }
}

fn setup(adjust: impl FnOnce(&mut Config)) -> Harness {
    setup_with(client_key(), adjust, None)
}

impl Harness {
    /// Moves bytes both ways until neither side makes progress.
    fn pump(&mut self) -> Result<(), Error> {
        for _ in 0..100_000 {
            let mut progress = false;
            let pending = self.client.tx.pending();
            let space = self.server.read_buf();
            let n = pending.len().min(space.len());
            if n > 0 {
                space[..n].copy_from_slice(&pending[..n]);
                self.server.read_done(n);
                self.client.tx.advance(n);
                progress = true;
            }
            while let Some(event) = self.server.poll()? {
                self.app.on_event(event);
                progress = true;
            }
            progress |= self.app.run(&mut self.server, self.scratch)?;
            let pending = self.server.write_buf();
            if !pending.is_empty() {
                let n = self.client.feed(pending);
                self.server.write_done(n);
                progress |= n > 0;
            }
            self.client.process()?;
            if !progress {
                return Ok(());
            }
        }
        panic!("pump did not settle");
    }

    /// Delivers client -> server traffic only: the server reacts, but the
    /// client does not see the answers yet.
    fn deliver_to_server(&mut self) -> Result<(), Error> {
        let pending = self.client.tx.pending();
        let space = self.server.read_buf();
        let n = pending.len().min(space.len());
        space[..n].copy_from_slice(&pending[..n]);
        self.server.read_done(n);
        self.client.tx.advance(n);
        while let Some(event) = self.server.poll()? {
            self.app.on_event(event);
        }
        Ok(())
    }

    fn login(&mut self) {
        self.pump().unwrap();
        assert!(self.client.session_id.is_some());
        self.client.service_request().unwrap();
        self.pump().unwrap();
        assert!(self.client.service_accepted);
        self.client.auth(true).unwrap();
        self.pump().unwrap();
        assert!(self.client.authenticated);
        assert!(self.server.is_authenticated());
        assert_eq!(self.server.user(), Some("tester"));
    }

    fn exec(&mut self, command: &[u8]) {
        self.client.open_session().unwrap();
        self.pump().unwrap();
        assert!(self.client.channel.is_some());
        self.client.exec(command).unwrap();
        self.pump().unwrap();
        assert_eq!(self.app.command.as_deref(), Some(command));
    }

    /// Streams `total` bytes through the echoing app and back.
    fn echo(&mut self, total: u64, client_rekey_every: Option<u64>) {
        let target = self.client.sent + total;
        let every = client_rekey_every.unwrap_or(u64::MAX);
        let mut next_rekey = self.client.sent.saturating_add(every);
        for _ in 0..1_000_000 {
            if self.client.received >= target {
                return;
            }
            if self.client.sent < target {
                let want = (target - self.client.sent).min(32 * 1024) as usize;
                self.client.send_data(want).unwrap();
            }
            if self.client.sent >= next_rekey {
                self.client.rekey().unwrap();
                next_rekey = next_rekey.saturating_add(every);
            }
            self.pump().unwrap();
        }
        panic!("echo stalled at {} of {}", self.client.received, target);
    }
}

/// Re-exchanges before authentication follow RFC 4253, up to a cap.
#[test]
fn rekeys_before_authentication_are_allowed_up_to_a_cap() {
    let mut h = setup(|_| {});
    h.pump().unwrap();
    h.client.rekey().unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.exchanges, 2);
    h.login();
    h.exec(b"cat");
    h.echo(1000, None);

    let mut h = setup(|_| {});
    h.pump().unwrap();
    for _ in 0..4 {
        h.client.rekey().unwrap();
        h.pump().unwrap();
    }
    assert_eq!(h.client.exchanges, 5);
    h.client.rekey().unwrap();
    assert!(matches!(h.pump(), Err(Error::Protocol(_))));
}

/// Moves bytes between `client` and the socket until `done` holds.
#[cfg(target_os = "linux")]
async fn exchange(
    stream: &mut tokio::net::TcpStream,
    client: &mut Client<'_>,
    done: impl Fn(&Client<'_>) -> bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let pending = client.tx.pending();
        if !pending.is_empty() {
            stream.write_all(pending).await.unwrap();
            let n = pending.len();
            client.tx.advance(n);
        }
        if done(client) {
            return;
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buf))
            .await
            .expect("the server went quiet")
            .unwrap();
        assert!(n > 0, "the server closed the connection");
        let mut fed = 0;
        while fed < n {
            fed += client.feed(&buf[fed..n]);
            client.process().unwrap();
        }
    }
}

/// Feeds `client` whatever the socket has right now, without waiting.
#[cfg(target_os = "linux")]
fn drain_ready(stream: &tokio::net::TcpStream, client: &mut Client<'_>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match stream.try_read(&mut buf) {
            Ok(0) => panic!("the server closed the connection"),
            Ok(n) => {
                let mut fed = 0;
                while fed < n {
                    fed += client.feed(&buf[fed..n]);
                    client.process().unwrap();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) => panic!("{e}"),
        }
    }
}

/// The real driver serving one connection with `/bin/sh` as the shell, and
/// a client logged in over TCP.
#[cfg(target_os = "linux")]
async fn tcp_login() -> (tokio::net::TcpStream, Client<'static>) {
    tcp_login_with(|_| {}).await
}

#[cfg(target_os = "linux")]
async fn tcp_login_with(
    adjust: impl FnOnce(&mut Config),
) -> (tokio::net::TcpStream, Client<'static>) {
    let authorized = client_key().public_key();
    let mut config = Config::new(
        HostKey::from_seed(&[7; 32]),
        AuthorizedKeys::from(vec![authorized]),
    );
    config.shell = Some("/bin/sh".into());
    adjust(&mut config);
    let config: &'static Config = Box::leak(Box::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        crate::serve_connection(stream, config).await
    });
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut client = new_client(client_key(), None);
    client.start().unwrap();
    exchange(&mut stream, &mut client, |c| c.exchanges == 1).await;
    client.service_request().unwrap();
    exchange(&mut stream, &mut client, |c| c.service_accepted).await;
    client.auth(true).unwrap();
    exchange(&mut stream, &mut client, |c| c.authenticated).await;
    (stream, client)
}

/// With the real driver and process: the end of a session is reported
/// while the client's window is closed, and output waits for the window.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn exit_is_reported_while_the_window_is_closed() {
    let (mut stream, mut client) = tcp_login().await;
    client.open_window = 0;

    // No output: EOF, the status and CLOSE need no window.
    client.open_session().unwrap();
    exchange(&mut stream, &mut client, |c| c.channel.is_some()).await;
    client.exec(b"exit 3").unwrap();
    exchange(&mut stream, &mut client, |c| c.closed).await;
    assert_eq!(client.exit_status, Some(3));
    assert!(client.eof);
    exchange(&mut stream, &mut client, |c| c.channel.is_some()).await;

    // Output waits for the window; the status follows it.
    client.channel = None;
    client.open_session().unwrap();
    exchange(&mut stream, &mut client, |c| c.channel.is_some()).await;
    client.received = 0;
    client.exec(b"printf 'abc'; exit 4").unwrap();
    exchange(&mut stream, &mut client, |c| c.successes >= 2).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drain_ready(&stream, &mut client);
    assert_eq!((client.received, client.exit_status), (0, None));
    client.adjust_window(1).unwrap();
    exchange(&mut stream, &mut client, |c| c.received == 1).await;
    assert_eq!(client.exit_status, None);
    client.adjust_window(10).unwrap();
    exchange(&mut stream, &mut client, |c| c.closed).await;
    assert_eq!((client.received, client.exit_status), (3, Some(4)));
}

/// Whether process `pid` exists and has not exited.
#[cfg(target_os = "linux")]
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| Some(stat.rsplit_once(')')?.1.trim_start().chars().next()? != 'Z'))
        .unwrap_or(false)
}

/// Opens a session whose shell starts `sleep 30` in the background (with
/// `redirect`) and exits; returns the sleep's PID.
#[cfg(target_os = "linux")]
async fn leave_a_job(
    stream: &mut tokio::net::TcpStream,
    client: &mut Client<'_>,
    name: &str,
    redirect: &str,
) -> u32 {
    let path = std::env::temp_dir().join(format!("tinyssh-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    client.open_session().unwrap();
    exchange(stream, client, |c| c.channel.is_some()).await;
    let command = format!("sleep 30 {redirect} & echo $! > {}; exit 0", path.display());
    client.exec(command.as_bytes()).unwrap();
    for _ in 0..500 {
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(pid) = text.strip_suffix('\n').and_then(|t| t.parse().ok())
        {
            std::fs::remove_file(&path).unwrap();
            return pid;
        }
        exchange(stream, client, |_| true).await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the shell did not start the job");
}

/// Closing a session hangs up its process group even after the shell has
/// exited: here a job still holds the output pipe, so the session could not
/// finish by itself.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn hangup_reaches_jobs_the_shell_left_behind() {
    let (mut stream, mut client) = tcp_login().await;
    let pid = leave_a_job(&mut stream, &mut client, "hangup", "").await;
    // Long enough for the shell to exit and the server to notice.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(running(pid));
    client.close().unwrap();
    exchange(&mut stream, &mut client, |c| c.closed).await;
    assert_eq!(client.exit_status, None);
    for _ in 0..500 {
        if !running(pid) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let _ = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status();
    panic!("the job survived the hang-up");
}

/// Input that arrives after the shell exited is dropped. A terminal would
/// otherwise take some of it and then block forever (nothing reads it), so
/// the client's window would never reopen; here the client holds output
/// back (its own window is closed), so the session cannot end meanwhile.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn input_stops_when_the_shell_exits() {
    let (mut stream, mut client) = tcp_login_with(|c| c.window_size = 32 * 1024).await;
    client.open_window = 0;
    client.open_session().unwrap();
    exchange(&mut stream, &mut client, |c| c.channel.is_some()).await;
    client.pty(b"xterm", 80, 24).unwrap();
    client.exec(b"printf x; exit 0").unwrap();
    exchange(&mut stream, &mut client, |c| c.successes >= 2).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Fill the window the server granted: more than a terminal buffers.
    assert_eq!(client.send_window, 32 * 1024);
    while client.send_window > 0 {
        client.send_data(client.send_window as usize).unwrap();
        exchange(&mut stream, &mut client, |_| true).await;
    }
    exchange(&mut stream, &mut client, |c| c.send_window > 0).await;
    client.adjust_window(1).unwrap();
    exchange(&mut stream, &mut client, |c| c.closed).await;
    assert_eq!((client.received, client.exit_status), (1, Some(0)));
}

/// A shell still running when its session is closed is hung up and then
/// reaped, not left behind as a zombie.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn hung_up_shells_are_reaped() {
    let (mut stream, mut client) = tcp_login().await;
    let path = std::env::temp_dir().join(format!("tinyssh-{}-reaped", std::process::id()));
    let _ = std::fs::remove_file(&path);
    client.open_session().unwrap();
    exchange(&mut stream, &mut client, |c| c.channel.is_some()).await;
    let command = format!("echo $$ > {}; exec sleep 30", path.display());
    client.exec(command.as_bytes()).unwrap();
    let mut pid = None;
    for _ in 0..500 {
        exchange(&mut stream, &mut client, |_| true).await;
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Some(p) = text.strip_suffix('\n').and_then(|t| t.parse::<u32>().ok())
        {
            pid = Some(p);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let pid = pid.expect("the shell did not start");
    std::fs::remove_file(&path).unwrap();
    assert!(running(pid));
    client.close().unwrap();
    exchange(&mut stream, &mut client, |c| c.closed).await;
    for _ in 0..500 {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the shell was not reaped (running: {})", running(pid));
}

/// A session that runs to completion signals nothing: a job that let go of
/// the session's output keeps running, as with OpenSSH.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn finished_sessions_leave_background_jobs_running() {
    let (mut stream, mut client) = tcp_login().await;
    let pid = leave_a_job(&mut stream, &mut client, "finished", "> /dev/null 2>&1").await;
    exchange(&mut stream, &mut client, |c| c.closed).await;
    assert_eq!(client.exit_status, Some(0));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let alive = running(pid);
    let _ = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status();
    assert!(alive, "the job was signalled when the session finished");
}

#[test]
fn exec_session_echoes_data_and_reports_exit_status() {
    let mut h = setup(|_| {});
    h.login();
    h.app.exit_on_eof = Some(3);
    h.exec(b"cat");
    h.echo(1 << 20, None);
    h.client.send_eof().unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.received, 1 << 20);
    assert_eq!(h.client.mismatches, 0);
    assert_eq!(h.client.exit_status, Some(3));
    assert!(h.client.eof && h.client.closed);
    assert_eq!(h.client.violations, 0);
    // The channel is gone, so a new session can be opened.
    h.app = App::default();
    h.exec(b"second");
    assert_eq!(h.app.spawned, 1);
}

#[test]
fn output_is_split_to_the_clients_packet_size() {
    let mut h = setup(|_| {});
    h.login();
    h.client.accept_packet = 1000;
    h.exec(b"cat");
    h.echo(300_000, None);
    assert_eq!(h.client.mismatches, 0);
    assert_eq!(h.client.oversized, 0);
}

#[test]
fn small_window_wraps_the_stdin_ring() {
    let mut h = setup(|c| c.window_size = 32 * 1024);
    h.login();
    h.exec(b"cat");
    h.echo(3 << 20, None);
    assert_eq!(h.client.mismatches, 0);
}

/// Zero dimensions are unspecified: before the shell starts they keep the
/// requested ones; afterwards they go to the platform, which keeps the
/// terminal's current ones.
#[test]
fn window_changes_keep_unspecified_dimensions() {
    let mut h = setup(|_| {});
    h.login();
    h.client.open_session().unwrap();
    h.pump().unwrap();
    h.client.pty(b"xterm", 120, 40).unwrap();
    h.client.window_change(0, 50).unwrap();
    h.client.exec(b"cat").unwrap();
    h.pump().unwrap();
    assert_eq!(h.app.size, Some((120, 50)));
    h.client.window_change(100, 0).unwrap();
    h.pump().unwrap();
    assert_eq!(h.app.resized, Some((100, 0)));
    let size = |cols, rows, width, height| WinSize {
        cols,
        rows,
        width,
        height,
    };
    let current = size(100, 30, 800, 600);
    assert_eq!(current.apply(size(0, 50, 0, 0)), size(100, 50, 800, 600));
    assert_eq!(current.apply(size(132, 0, 1, 0)), size(132, 30, 1, 600));
    assert_eq!(current.apply(size(0, 0, 0, 0)), current);
}

#[test]
fn pty_shell_and_window_change() {
    let mut h = setup(|_| {});
    h.login();
    h.client.open_session().unwrap();
    h.pump().unwrap();
    h.client.pty(b"xterm-256color", 120, 40).unwrap();
    h.client
        .request(b"env", true, |w| {
            w.put_string(b"LANG").and_then(|()| w.put_string(b"C"))
        })
        .unwrap();
    h.client.request(b"shell", true, |_| Ok(())).unwrap();
    h.pump().unwrap();
    assert_eq!((h.client.successes, h.client.failures), (2, 1));
    assert_eq!(h.app.command, None);
    assert_eq!(h.app.term.as_deref(), Some("xterm-256color"));
    assert_eq!(h.app.size, Some((120, 40)));
    h.client.window_change(100, 30).unwrap();
    h.pump().unwrap();
    assert_eq!(h.app.resized, Some((100, 30)));
    // A second shell (or exec) after the start is refused.
    h.client.request(b"shell", true, |_| Ok(())).unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.failures, 2);
    assert_eq!(h.app.spawned, 1);
}

#[test]
fn client_close_hangs_up_the_session() {
    let mut h = setup(|_| {});
    h.login();
    h.exec(b"sleep 100");
    h.client.close().unwrap();
    h.pump().unwrap();
    assert_eq!(h.app.hangups, 1);
    assert!(h.client.closed);
    assert_eq!(h.client.exit_status, None);
}

#[test]
fn spawn_failure_is_reported_on_stderr() {
    let mut h = setup(|_| {});
    h.login();
    h.app.fail_with = Some((b"no such command\r\n", 127));
    h.exec(b"missing");
    h.pump().unwrap();
    assert_eq!(h.client.stderr, 17);
    assert_eq!(h.client.exit_status, Some(127));
}

/// A session whose packets could hold no data could never end.
#[test]
fn channels_without_room_for_data_are_refused() {
    let mut h = setup(|_| {});
    h.login();
    h.client.accept_packet = 0;
    h.client.open_session().unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.open_failures, 1);
    assert_eq!(h.client.channel, None);
    h.client.accept_packet = 32 * 1024;
    h.exec(b"cat");
    h.echo(1000, None);
}

#[test]
fn only_one_session_at_a_time() {
    let mut h = setup(|_| {});
    h.login();
    h.exec(b"first");
    h.client.open_session().unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.open_failures, 1);
    h.client
        .packet(|w| {
            w.put_u8(msg::CHANNEL_OPEN)?;
            w.put_string(b"direct-tcpip")?;
            for v in [9, 1024, 1024] {
                w.put_u32(v)?;
            }
            Ok(())
        })
        .unwrap();
    h.client.global_request(true).unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.open_failures, 2);
    assert_eq!(h.client.request_failures, 1);
}

#[test]
fn rekeys_initiated_by_both_sides_under_load() {
    let mut h = setup(|c| c.rekey_limit = 64 * 1024);
    h.login();
    h.exec(b"cat");
    let before = h.client.exchanges;
    h.echo(4 << 20, Some(300 * 1024));
    // Each direction carries 4 MiB, so the server alone rekeys >= 64 times.
    let exchanges = h.client.exchanges - before;
    assert!(exchanges >= 64, "only {exchanges} exchanges");
    assert_eq!(h.client.mismatches, 0);
    assert_eq!(h.client.violations, 0);
}

#[test]
fn rekeying_after_every_packet_still_works() {
    let mut h = setup(|c| c.rekey_limit = 1);
    h.login();
    h.exec(b"cat");
    h.echo(256 * 1024, None);
    assert_eq!(h.client.mismatches, 0);
    assert_eq!(h.client.violations, 0);
    assert!(h.client.exchanges > 10);
}

#[test]
fn replies_are_held_back_while_the_server_rekeys() {
    let mut h = setup(|_| {});
    h.login();
    h.exec(b"cat");
    // The server starts a key exchange; before the client sees its KEXINIT
    // it sends requests that need replies, plus data to be echoed.
    h.server.force_rekey().unwrap();
    h.client.global_request(true).unwrap();
    h.client.request(b"x11-req", true, |_| Ok(())).unwrap();
    h.client.send_data(1000).unwrap();
    h.deliver_to_server().unwrap();
    assert_eq!(
        h.server.output_room(),
        0,
        "no channel data while the KEXINIT is out"
    );
    h.pump().unwrap();
    assert_eq!(h.client.violations, 0);
    assert_eq!(h.client.request_failures, 1);
    assert_eq!(h.client.failures, 1);
    assert_eq!(h.client.received, 1000);
    assert_eq!(h.client.exchanges, 2);
}

#[test]
fn query_then_signed_authentication() {
    let mut h = setup(|_| {});
    h.pump().unwrap();
    h.client.service_request().unwrap();
    h.client.auth(false).unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.pk_ok, 1);
    assert!(!h.client.authenticated);
    h.client.auth(true).unwrap();
    h.pump().unwrap();
    assert!(h.client.authenticated);
}

#[test]
fn unauthorized_key_is_refused_and_disconnected() {
    let mut h = setup_with(
        HostKey::from_seed(&[1; 32]),
        |c| c.max_auth_attempts = 3,
        None,
    );
    h.pump().unwrap();
    h.client.service_request().unwrap();
    for _ in 0..2 {
        h.client.auth(true).unwrap();
        h.pump().unwrap();
    }
    assert_eq!(h.client.auth_failures, 2);
    h.client.auth(false).unwrap();
    let err = h.pump().unwrap_err();
    assert!(
        matches!(err, Error::Protocol("too many authentication failures")),
        "{err}"
    );
    let _ = h.pump();
    assert_eq!(h.client.disconnect, Some(reason::NO_MORE_AUTH_METHODS));
    assert!(!h.server.is_authenticated());
}

#[test]
fn connection_messages_require_authentication() {
    let mut h = setup(|_| {});
    h.pump().unwrap();
    h.client.service_request().unwrap();
    h.client.open_session().unwrap();
    let err = h.pump().unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol("connection message before authentication")
        ),
        "{err}"
    );
}

#[test]
fn exceeding_the_window_is_a_protocol_error() {
    let mut h = setup(|c| c.window_size = 32 * 1024);
    h.login();
    h.exec(b"stuck");
    h.app.running = false; // the process does not read its input
    h.client.send_window = u32::MAX;
    for _ in 0..3 {
        h.client.send_data(16 * 1024).unwrap();
    }
    let err = h.pump().unwrap_err();
    assert!(
        matches!(err, Error::Protocol("channel window exceeded")),
        "{err}"
    );
}

#[test]
fn client_extended_data_consumes_and_regains_window() {
    let mut h = setup(|c| c.window_size = 32 * 1024);
    h.login();
    h.exec(b"cat");
    // Eight windows' worth of (discarded) extended data: it only gets through
    // if the server keeps granting that window back.
    let mut sent = 0;
    for _ in 0..10_000 {
        if sent >= 256 * 1024 {
            break;
        }
        sent += h.client.send_extended(16 * 1024).unwrap();
        h.pump().unwrap();
    }
    assert_eq!(sent, 256 * 1024);
    h.echo(64 * 1024, None);
    assert_eq!(h.client.mismatches, 0);
    // Extended data beyond the window is a violation like normal data: with
    // stdin no longer drained, 16 KiB stay buffered and 32 KiB cannot fit.
    h.app.running = false;
    h.client.send_window = u32::MAX;
    h.client.send_data(16 * 1024).unwrap();
    h.client.send_extended(32 * 1024).unwrap();
    let err = h.pump().unwrap_err();
    assert!(
        matches!(err, Error::Protocol("channel window exceeded")),
        "{err}"
    );
}

#[test]
fn tampered_packet_fails_authentication() {
    let mut h = setup(|_| {});
    h.login();
    h.client.global_request(false).unwrap();
    let pending = h.client.tx.pending().len();
    let space = h.server.read_buf();
    space[..pending].copy_from_slice(h.client.tx.pending());
    space[pending - 20] ^= 1; // flip a ciphertext bit
    h.server.read_done(pending);
    h.client.tx.advance(pending);
    assert!(matches!(h.server.poll(), Err(Error::Mac)));
    assert!(h.server.is_closed());
    let n = h.client.feed(h.server.write_buf());
    h.server.write_done(n);
    let _ = h.client.process();
    assert_eq!(h.client.disconnect, Some(reason::MAC_ERROR));
}

/// Writes the identification line, an IGNORE, then KEXINIT.
fn ignore_before_kexinit(h: &mut Harness, style: Option<KexStyle>) {
    h.client = new_client(client_key(), style);
    h.client.tx.raw(client::VERSION).unwrap();
    h.client.tx.raw(b"\r\n").unwrap();
    h.client.packet(|w| w.put_u8(msg::IGNORE)).unwrap();
    h.client.send_kexinit().unwrap();
}

#[test]
fn strict_kex_requires_kexinit_first() {
    let mut h = setup(|_| {});
    ignore_before_kexinit(&mut h, None);
    let err = h.pump().unwrap_err();
    assert!(
        matches!(
            err,
            Error::Protocol("strict KEX: KEXINIT was not the first packet")
        ),
        "{err}"
    );
}

#[test]
fn ignore_before_kexinit_is_fine_without_strict_kex() {
    let mut h = setup(|_| {});
    ignore_before_kexinit(
        &mut h,
        Some(KexStyle {
            kex: b"curve25519-sha256",
            guess: false,
        }),
    );
    h.login();
}

#[test]
fn wrong_kex_guess_is_ignored() {
    let style = KexStyle {
        kex: b"ecdh-sha2-nistp256,curve25519-sha256",
        guess: true,
    };
    let mut h = setup_with(client_key(), |_| {}, Some(style));
    h.login();
    h.exec(b"cat");
    h.echo(10_000, None);
    assert_eq!(h.client.mismatches, 0);
}

#[test]
fn no_common_algorithm_disconnects() {
    let style = KexStyle {
        kex: b"diffie-hellman-group14-sha256",
        guess: false,
    };
    let mut h = setup_with(client_key(), |_| {}, Some(style));
    let err = h.pump().unwrap_err();
    assert!(
        matches!(err, Error::Protocol(text) if text.contains("curve25519-sha256")),
        "{err}"
    );
    let _ = h.pump();
    assert_eq!(h.client.disconnect, Some(reason::KEY_EXCHANGE_FAILED));
}

#[test]
fn rejects_non_ssh2_clients() {
    let mut h = setup(|_| {});
    let space = h.server.read_buf();
    space[..13].copy_from_slice(b"SSH-1.5-old\r\n");
    h.server.read_done(13);
    assert!(matches!(
        h.server.poll(),
        Err(Error::Protocol("unsupported protocol version"))
    ));
}

#[test]
fn unknown_messages_get_unimplemented() {
    let mut h = setup(|_| {});
    h.login();
    h.client.packet(|w| w.put_u8(200)).unwrap();
    h.pump().unwrap();
    assert_eq!(h.client.unimplemented, 1);
}

#[test]
fn wire_codec_follows_rfc4251_and_rejects_truncation() {
    use crate::wire::{Buf, Msg};
    // The mpint examples of RFC 4251 §5; leading zero bytes must not matter.
    let examples: [(&[u8], &[u8]); 3] = [
        (&[], &[0, 0, 0, 0]),
        (
            &[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
            &[0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        ),
        (&[0x80], &[0, 0, 0, 2, 0, 0x80]),
    ];
    for (value, encoded) in examples {
        for zeros in [0, 3] {
            let mut input = vec![0u8; zeros];
            input.extend_from_slice(value);
            let mut out = [0u8; 16];
            let mut w = Buf::new(&mut out);
            w.put_mpint(&input).unwrap();
            let n = w.len();
            assert_eq!(&out[..n], encoded);
        }
    }
    let mut m = Msg::new(&[0, 0, 0, 2, b'h', b'i', 7]);
    assert_eq!(m.string().unwrap(), b"hi");
    assert!(m.bool().unwrap());
    assert!(m.end().is_ok());
    // Lengths running past the end are errors, not panics.
    assert!(Msg::new(&[0, 0, 0, 3, b'a', b'b']).string().is_err());
    assert!(Msg::new(&[0xff, 0xff, 0xff, 0xff]).string().is_err());
    assert!(Msg::new(&[0, 0, 1]).u32().is_err());
    assert!(Msg::new(&[0, 0, 0, 31]).fixed_string::<32>().is_err());
    // Writes that do not fit fail instead of truncating.
    assert!(Buf::new(&mut [0u8; 5]).put_string(b"hi").is_err());
}

#[test]
#[cfg(target_arch = "x86_64")]
#[allow(clippy::assertions_on_constants)] // checks the build configuration
fn built_for_avx2_with_aes_ni() {
    assert!(cfg!(target_feature = "avx2"));
    assert!(cfg!(target_feature = "aes"));
    assert!(cfg!(target_feature = "pclmulqdq"));
}

/// Once a session is streaming nothing allocates: not the server core, not
/// rekeying in either direction, not flow control or channel requests.
#[test]
#[cfg(debug_assertions)]
fn steady_state_does_not_allocate() {
    let mut h = setup(|c| c.rekey_limit = 128 * 1024);
    h.login();
    h.exec(b"cat");
    // Warm up every path once.
    h.echo(512 * 1024, Some(200 * 1024));
    h.client.window_change(90, 30).unwrap();
    h.client.global_request(true).unwrap();
    h.pump().unwrap();
    let exchanges = h.client.exchanges;
    // Positive control: the counter sees allocations on this thread.
    let ((), control) = alloc::measure(|| drop(std::hint::black_box(Vec::<u8>::with_capacity(64))));
    assert_eq!(control, 1);
    let ((), allocations) = alloc::measure(|| {
        for round in 0..16u32 {
            h.echo(256 * 1024, Some(96 * 1024));
            h.client.window_change(80 + round, 24).unwrap();
            h.client.global_request(true).unwrap();
            h.client
                .request(b"env", true, |w| {
                    w.put_string(b"A").and_then(|()| w.put_string(b"B"))
                })
                .unwrap();
            h.pump().unwrap();
        }
    });
    assert_eq!(allocations, 0, "allocations in steady state");
    assert!(h.client.exchanges - exchanges >= 32);
    assert_eq!(h.client.mismatches, 0);
    assert_eq!(h.client.violations, 0);
    assert_eq!(h.client.request_failures, 17);
}

#[test]
fn pattern_wraps_at_251() {
    assert_eq!(pattern(250, 3), &[250, 0, 1]);
}
