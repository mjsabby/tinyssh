//! The tokio driver: accepts TCP connections and connects each [`Connection`]
//! to its socket and session process from a single task, without sharing
//! any state between tasks.

use crate::conn::{Arena, Connection, Event};
use crate::sys::{Chunk, Process};
use crate::{Config, Error};
use std::io;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, sleep, sleep_until, timeout};

/// Accepts connections forever, serving each one on its own tokio task.
///
/// At most [`Config::max_connections`] connections are served at once; extra
/// connections are closed immediately. Accept errors (such as running out of
/// file descriptors) are retried after a short pause. The runtime must have
/// I/O and time enabled.
pub async fn serve(listener: TcpListener, config: &'static Config) -> ! {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(admission) = config.admit() else {
            continue;
        };
        tokio::spawn(async move {
            let _admission = admission;
            let _ = serve_connection(stream, config).await;
        });
    }
}

/// Serves one client until it disconnects.
///
/// Returns `Ok(())` when the client goes away and an error if the connection
/// failed (protocol violation, I/O error, login timeout).
pub async fn serve_connection(stream: TcpStream, config: &Config) -> Result<(), Error> {
    let _ = stream.set_nodelay(true);
    let mut arena = Arena::new(config);
    let (memory, scratch) = arena.split();
    let mut conn = Connection::new(config, memory)?;
    let mut session = Session {
        process: None,
        exit: None,
        drained: false,
        pending: Pending::default(),
    };
    let deadline = Instant::now().checked_add(config.login_timeout);
    let result = drive(&stream, &mut conn, &mut session, scratch, config, deadline).await;
    if let Some(process) = session.process.take() {
        process.hangup();
    }
    // Best effort: deliver a final DISCONNECT, if any.
    let _ = timeout(Duration::from_secs(1), flush(&stream, &mut conn)).await;
    match result {
        Err(Error::Disconnected) => Ok(()),
        other => other,
    }
}

struct Session {
    process: Option<Process>,
    /// Exit code, once the process has exited.
    exit: Option<u32>,
    /// All output has been read.
    drained: bool,
    pending: Pending,
}

/// Process output read but not yet sent: `scratch[start..end]`. Output is
/// read whether or not the client's window has room, one chunk at a time, so
/// that the end of the output (and then the exit status) is noticed even
/// while the window is full; the chunk goes out as the window opens.
#[derive(Default)]
struct Pending {
    stderr: bool,
    start: usize,
    end: usize,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

enum Wake {
    Readable(io::Result<()>),
    Writable(io::Result<()>),
    Input(io::Result<usize>),
    Output(io::Result<Chunk>),
    Exit(io::Result<u32>),
    Timeout,
    Stalled,
}

async fn drive(
    stream: &TcpStream,
    conn: &mut Connection<'_>,
    session: &mut Session,
    scratch: &mut [u8],
    config: &Config,
    deadline: Option<Instant>,
) -> Result<(), Error> {
    loop {
        // Gives way to other tasks and the timers now and then: a peer that
        // keeps the socket busy must not monopolize the runtime.
        tokio::task::coop::consume_budget().await;
        while let Some(event) = conn.poll()? {
            match event {
                Event::Spawn(request) => {
                    let spawned = Process::spawn(&request, config).await;
                    session.exit = None;
                    session.drained = false;
                    session.pending = Pending::default();
                    match spawned {
                        Ok(process) => session.process = Some(process),
                        Err(e) => spawn_failed(conn, &e)?,
                    }
                }
                Event::Resize(size) => {
                    if let Some(process) = &mut session.process {
                        process.resize(size);
                    }
                }
                Event::Hangup => {
                    if let Some(process) = session.process.take() {
                        process.hangup();
                    }
                    session.pending = Pending::default();
                }
            }
        }

        // Send as much of the pending output as the window allows.
        loop {
            let pending = &mut session.pending;
            let len = pending.end.saturating_sub(pending.start);
            let n = len.min(conn.output_room());
            if n == 0 {
                break;
            }
            let end = pending.start.saturating_add(n);
            conn.output(
                pending.stderr,
                scratch.get(pending.start..end).unwrap_or_default(),
            )?;
            pending.start = end;
        }

        if let Some(process) = &mut session.process {
            if conn.stdin_closed() {
                process.input.close();
            }
            // Input the process can no longer take is discarded so the
            // client's window keeps moving.
            if !process.input.is_open() {
                while !conn.stdin().is_empty() {
                    conn.stdin_consumed(conn.stdin().len())?;
                }
            }
            if let (Some(code), true) =
                (session.exit, session.drained && session.pending.is_empty())
            {
                if let Some(process) = session.process.take() {
                    process.finish();
                }
                conn.exited(code)?;
                continue;
            }
        }

        // Socket writes go through `Wake::Writable` only: it returns to the
        // top of the loop, which resumes processing buffered packets if the
        // send buffer had been too full for them.
        if conn.is_closed() {
            return Ok(());
        }

        let want_write = !conn.write_buf().is_empty();
        let want_read = conn.wants_read();
        let want_timeout = !conn.is_authenticated() && deadline.is_some();
        // Checked here as well: the timer fires only when the runtime gets
        // around to it, which a busy connection can delay.
        if want_timeout && deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Error::Timeout);
        }
        let running = session.process.is_some();
        let want_output = running && !session.drained && session.pending.is_empty();
        let want_exit = running && session.exit.is_none();
        let stdin = conn.stdin();
        let (input, output, waiter) = match session.process.as_mut() {
            Some(p) => (Some(&mut p.input), Some(&mut p.output), Some(&mut p.waiter)),
            None => (None, None, None),
        };
        let want_input = !stdin.is_empty() && input.as_ref().is_some_and(|input| input.is_open());
        // The login deadline comes first: a peer that keeps the socket busy
        // must not be able to starve it.
        let wake = tokio::select! {
            biased;
            () = sleep_until(deadline.unwrap_or_else(Instant::now)), if want_timeout => Wake::Timeout,
            r = stream.writable(), if want_write => Wake::Writable(r),
            r = stream.readable(), if want_read => Wake::Readable(r),
            r = write_input(input, stdin), if want_input => Wake::Input(r),
            r = read_output(output, scratch), if want_output => Wake::Output(r),
            r = wait_exit(waiter), if want_exit => Wake::Exit(r),
            else => Wake::Stalled,
        };

        match wake {
            Wake::Writable(ready) => {
                ready?;
                match stream.try_write(conn.write_buf()) {
                    Ok(n) => conn.write_done(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Wake::Readable(ready) => {
                ready?;
                match stream.try_read(conn.read_buf()) {
                    Ok(0) => return Err(Error::Disconnected),
                    Ok(n) => conn.read_done(n),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Wake::Input(Ok(n)) => conn.stdin_consumed(n)?,
            Wake::Input(Err(_)) => {
                if let Some(process) = &mut session.process {
                    process.input.broken();
                }
            }
            Wake::Output(Ok(Chunk::Stdout(n))) => {
                session.pending = Pending {
                    stderr: false,
                    start: 0,
                    end: n,
                };
            }
            Wake::Output(Ok(Chunk::Stderr(n))) => {
                session.pending = Pending {
                    stderr: true,
                    start: 0,
                    end: n,
                };
            }
            Wake::Output(Ok(Chunk::Eof) | Err(_)) => session.drained = true,
            Wake::Exit(code) => {
                session.exit = Some(code.unwrap_or(255));
                // Input stops with the shell (as with OpenSSH): a terminal
                // would otherwise buffer or echo it, and never refuse it.
                if let Some(process) = &mut session.process {
                    process.input.broken();
                    process.output.exited();
                }
            }
            Wake::Timeout => return Err(Error::Timeout),
            Wake::Stalled => return Err(Error::Protocol("connection stalled")),
        }
    }
}

/// Tells the client why its session did not start.
fn spawn_failed(conn: &mut Connection<'_>, e: &io::Error) -> Result<(), Error> {
    let text = format!("tinyssh: cannot start session: {e}\r\n");
    let shown = text.len().min(conn.output_room());
    conn.output(true, text.as_bytes().get(..shown).unwrap_or_default())?;
    conn.exited(127)
}

async fn write_input(input: Option<&mut crate::sys::Input>, data: &[u8]) -> io::Result<usize> {
    match input {
        Some(input) => input.write(data).await,
        None => std::future::pending().await,
    }
}

async fn read_output(output: Option<&mut crate::sys::Output>, buf: &mut [u8]) -> io::Result<Chunk> {
    match output {
        Some(output) => output.read(buf).await,
        None => std::future::pending().await,
    }
}

async fn wait_exit(waiter: Option<&mut crate::sys::Waiter>) -> io::Result<u32> {
    match waiter {
        Some(waiter) => waiter.wait().await,
        None => std::future::pending().await,
    }
}

async fn flush(stream: &TcpStream, conn: &mut Connection<'_>) -> io::Result<()> {
    while !conn.write_buf().is_empty() {
        stream.writable().await?;
        match stream.try_write(conn.write_buf()) {
            Ok(n) => conn.write_done(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
