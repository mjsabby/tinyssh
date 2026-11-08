//! Linux: pseudo-terminals from `/dev/ptmx`, pipes for plain `exec`, and
//! privilege dropping when running as root (e.g. from init).
//!
//! Only the C library that `std` already links is used, through a handful of
//! declarations below; ioctl numbers are the asm-generic ones shared by
//! x86-64 and aarch64.

use super::{Chunk, command_flag};
use crate::Config;
use crate::conn::{SpawnRequest, WinSize};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_int, c_long, c_uint, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::io::Interest;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};

mod ffi {
    use super::{c_int, c_long, c_uint, c_ulong, c_void};

    unsafe extern "C" {
        pub(super) fn getrandom(buf: *mut c_void, len: usize, flags: c_uint) -> isize;
        pub(super) fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        pub(super) fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
        pub(super) fn setgroups(len: usize, groups: *const u32) -> c_int;
        pub(super) safe fn setsid() -> c_int;
        pub(super) safe fn setgid(gid: u32) -> c_int;
        pub(super) safe fn setuid(uid: u32) -> c_int;
        pub(super) safe fn geteuid() -> u32;
        pub(super) safe fn kill(pid: c_int, signal: c_int) -> c_int;
        pub(super) safe fn fchown(fd: c_int, owner: u32, group: u32) -> c_int;
        pub(super) fn syscall(number: c_long, ...) -> c_long;
        pub(super) fn waitid(idtype: c_int, id: u32, info: *mut SigInfo, options: c_int) -> c_int;
    }

    pub(super) const SYS_PIDFD_OPEN: c_long = 434;
    pub(super) const P_PID: c_int = 1;
    pub(super) const WNOHANG: c_int = 1;
    pub(super) const WEXITED: c_int = 4;
    pub(super) const WNOWAIT: c_int = 0x0100_0000;
    pub(super) const CLD_EXITED: c_int = 1;

    /// `siginfo_t`, as `waitid` fills it in for a child.
    #[repr(C, align(8))]
    #[derive(Default)]
    pub(super) struct SigInfo {
        _signo: c_int,
        _errno: c_int,
        pub(super) code: c_int,
        _pad: c_int,
        pub(super) pid: c_int,
        _uid: u32,
        pub(super) status: c_int,
        _rest: [u32; 25],
    }

    const _: () = assert!(size_of::<SigInfo>() == 128);

    pub(super) const TIOCGWINSZ: c_ulong = 0x5413;
    pub(super) const TIOCSWINSZ: c_ulong = 0x5414;
    pub(super) const TIOCSCTTY: c_ulong = 0x540E;
    pub(super) const TIOCSPTLCK: c_ulong = 0x4004_5431;
    pub(super) const TIOCGPTPEER: c_ulong = 0x5441;
    pub(super) const F_GETFL: c_int = 3;
    pub(super) const F_SETFL: c_int = 4;
    pub(super) const F_SETPIPE_SZ: c_int = 1031;
    pub(super) const O_RDWR: c_int = 0o2;
    pub(super) const O_NOCTTY: c_int = 0o400;
    pub(super) const O_NONBLOCK: c_int = 0o4000;
    pub(super) const O_CLOEXEC: c_int = 0o2_000_000;
    pub(super) const EIO: i32 = 5;
    pub(super) const SIGHUP: c_int = 1;
    pub(super) const SIGCONT: c_int = 18;

    #[repr(C)]
    #[derive(Default)]
    pub(super) struct Winsize {
        pub(super) rows: u16,
        pub(super) cols: u16,
        pub(super) width: u16,
        pub(super) height: u16,
    }
}

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Capacity requested for session pipes (the default `pipe-max-size`). The
/// default 64 KiB pipe makes the session and the server exchange data in
/// small pieces, each costing system calls and wake-ups on both sides.
const PIPE_SIZE: c_int = 1 << 20;

/// Fills `buf` from the kernel CSPRNG (blocks until it is seeded).
pub(crate) fn os_random(mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: pointer and length describe a valid, writable buffer.
        let n = unsafe { ffi::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
        match usize::try_from(n) {
            Ok(n) => buf = core::mem::take(&mut buf).get_mut(n..).unwrap_or_default(),
            Err(_) => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

fn check(ret: c_int) -> io::Result<c_int> {
    match ret {
        ..0 => Err(io::Error::last_os_error()),
        ok => Ok(ok),
    }
}

/// Best effort: the kernel refuses sizes above its limits, which only costs
/// throughput.
fn grow_pipe(fd: RawFd) {
    // SAFETY: plain fcntl call on a descriptor we own.
    unsafe { ffi::fcntl(fd, ffi::F_SETPIPE_SZ, PIPE_SIZE) };
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl calls on a descriptor we own.
    let flags = check(unsafe { ffi::fcntl(fd, ffi::F_GETFL) })?;
    check(unsafe { ffi::fcntl(fd, ffi::F_SETFL, flags | ffi::O_NONBLOCK) }).map(drop)
}

fn register(file: File) -> io::Result<AsyncFd<File>> {
    // SAFETY: `File` owns its descriptor, which stays open and unchanged for
    // the lifetime of the `AsyncFd`.
    Ok(unsafe { AsyncFd::register(file) }?)
}

fn set_winsize(fd: RawFd, size: WinSize) -> io::Result<()> {
    let ws = ffi::Winsize {
        rows: size.rows,
        cols: size.cols,
        width: size.width,
        height: size.height,
    };
    // SAFETY: TIOCSWINSZ reads a `struct winsize` from the pointer.
    check(unsafe { ffi::ioctl(fd, ffi::TIOCSWINSZ, &raw const ws) }).map(drop)
}

/// Resizes the terminal behind `fd`; zero dimensions keep the current ones.
fn resize_pty(fd: RawFd, size: WinSize) -> io::Result<()> {
    let mut ws = ffi::Winsize::default();
    // SAFETY: TIOCGWINSZ writes a `struct winsize` to the pointer.
    check(unsafe { ffi::ioctl(fd, ffi::TIOCGWINSZ, &raw mut ws) })?;
    let current = WinSize {
        cols: ws.cols,
        rows: ws.rows,
        width: ws.width,
        height: ws.height,
    };
    set_winsize(fd, current.apply(size))
}

/// Opens a pseudo-terminal pair: (master, slave).
fn open_pty(size: WinSize) -> io::Result<(File, File)> {
    let master = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(ffi::O_NOCTTY)
        .open("/dev/ptmx")?;
    let fd = master.as_raw_fd();
    let unlock: c_int = 0;
    // SAFETY: TIOCSPTLCK reads an int; TIOCGPTPEER returns a new descriptor.
    check(unsafe { ffi::ioctl(fd, ffi::TIOCSPTLCK, &raw const unlock) })?;
    let flags = ffi::O_RDWR | ffi::O_NOCTTY | ffi::O_CLOEXEC;
    let slave = check(unsafe { ffi::ioctl(fd, ffi::TIOCGPTPEER, flags) })?;
    // SAFETY: `slave` is a freshly opened descriptor owned by nobody else.
    let slave = unsafe { File::from_raw_fd(slave) };
    set_winsize(fd, size)?;
    Ok((master, slave))
}

struct Account {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
    shell: String,
}

/// Finds an `/etc/passwd` entry: `name:password:uid:gid:gecos:home:shell`.
fn find_account(passwd: &str, matches: impl Fn(&str, u32) -> bool) -> Option<Account> {
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let uid = f.nth(1)?.parse().ok()?;
        let gid = f.next()?.parse().ok()?;
        let home = f.nth(1)?;
        let shell = f.next().unwrap_or_default();
        matches(name, uid).then(|| Account {
            name: name.into(),
            uid,
            gid,
            home: home.into(),
            shell: shell.into(),
        })
    })
}

fn passwd(matches: impl Fn(&str, u32) -> bool) -> Option<Account> {
    find_account(&std::fs::read_to_string("/etc/passwd").ok()?, matches)
}

/// Primary group plus supplementary groups from `/etc/group`
/// (`name:password:gid:member,member`).
fn find_groups(group: &str, user: &str, gid: u32) -> Vec<u32> {
    let mut ids = vec![gid];
    for line in group.lines() {
        let mut f = line.split(':');
        let (Some(id), Some(members)) = (f.nth(2), f.next()) else {
            continue;
        };
        if let Ok(id) = id.parse()
            && members.split(',').any(|m| m == user)
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    ids
}

fn groups(user: &str, gid: u32) -> Vec<u32> {
    find_groups(
        &std::fs::read_to_string("/etc/group").unwrap_or_default(),
        user,
        gid,
    )
}

/// The account to run as: the requested user when running as root,
/// otherwise the current user.
fn account(user: &str) -> io::Result<(Account, bool)> {
    let euid = ffi::geteuid();
    if euid == 0 {
        let found = passwd(|name, _| name == user);
        return found
            .map(|a| (a, true))
            .ok_or_else(|| io::Error::other(format!("unknown user {user:?}")));
    }
    let current = passwd(|_, uid| uid == euid).unwrap_or_else(|| Account {
        name: std::env::var("USER").unwrap_or_else(|_| user.into()),
        uid: euid,
        gid: 0,
        home: std::env::var("HOME").unwrap_or_else(|_| "/".into()),
        shell: String::new(),
    });
    Ok((current, false))
}

/// The session's process.
pub(crate) struct Process {
    pub(crate) input: Input,
    pub(crate) output: Output,
    pub(crate) waiter: Waiter,
}

impl Process {
    /// Starts the login shell or `exec` command for `req`.
    pub(crate) async fn spawn(req: &SpawnRequest<'_>, config: &Config) -> io::Result<Self> {
        let (account, switch_user) = account(req.user)?;
        let shell = [config.shell.as_deref(), Some(account.shell.as_str())]
            .into_iter()
            .flatten()
            .find(|s| !s.is_empty())
            .unwrap_or("/bin/sh")
            .to_owned();
        let mut cmd = Command::new(&shell);
        match req.command {
            Some(command) => {
                cmd.arg(command_flag(&shell))
                    .arg(OsStr::from_bytes(command));
            }
            None => {
                // A leading '-' in argv[0] asks for a login shell.
                let name = Path::new(&shell).file_name().unwrap_or(OsStr::new("sh"));
                cmd.arg0(format!("-{}", name.to_string_lossy()));
            }
        }
        let home = match Path::new(&account.home).is_dir() {
            true => account.home.as_str(),
            false => "/",
        };
        cmd.env_clear()
            .env("HOME", home)
            .env("USER", &account.name)
            .env("LOGNAME", &account.name)
            .env("SHELL", &shell)
            .env("PATH", PATH)
            .current_dir(home);
        let identity =
            switch_user.then(|| (account.uid, account.gid, groups(&account.name, account.gid)));
        let pty = req.pty.is_some();
        let user = identity.as_ref().map(|(uid, ..)| *uid);
        // SAFETY: the hook runs between fork and exec and only makes
        // async-signal-safe system calls on data prepared before the fork.
        unsafe {
            cmd.pre_exec(move || {
                check(ffi::setsid())?;
                if pty {
                    check(ffi::ioctl(0, ffi::TIOCSCTTY, 0))?;
                }
                if let Some((uid, gid, groups)) = &identity {
                    check(ffi::setgroups(groups.len(), groups.as_ptr()))?;
                    check(ffi::setgid(*gid))?;
                    check(ffi::setuid(*uid))?;
                }
                Ok(())
            });
        }
        if let Some(pty) = &req.pty {
            if !pty.term.is_empty() {
                cmd.env("TERM", pty.term);
            }
            let (master, slave) = open_pty(pty.size)?;
            // Like login, hand the terminal to the user (keeping the group
            // devpts gave it): programs that reopen it would fail otherwise.
            if let Some(uid) = user {
                check(ffi::fchown(slave.as_raw_fd(), uid, u32::MAX))?;
            }
            cmd.stdin(slave.try_clone()?)
                .stdout(slave.try_clone()?)
                .stderr(slave);
            // From here on, an early return hangs the process up (`Waiter`).
            let waiter = Waiter::new(cmd.spawn()?);
            // Drop our copies of the slave so EOF/EIO is seen when the session ends.
            drop(cmd);
            set_nonblocking(master.as_raw_fd())?;
            let input = master.try_clone()?;
            return Ok(Self {
                input: Input {
                    fd: Some(register(input)?),
                    pty: true,
                },
                output: Output::Pty {
                    master: register(master)?,
                    draining: false,
                },
                waiter,
            });
        }
        let (stdin, stdin_tx) = io::pipe()?;
        let (stdout_rx, stdout) = io::pipe()?;
        let (stderr_rx, stderr) = io::pipe()?;
        for fd in [
            stdin_tx.as_raw_fd(),
            stdout_rx.as_raw_fd(),
            stderr_rx.as_raw_fd(),
        ] {
            grow_pipe(fd);
        }
        cmd.stdin(stdin).stdout(stdout).stderr(stderr);
        // From here on, an early return hangs the process up (`Waiter`).
        let waiter = Waiter::new(cmd.spawn()?);
        drop(cmd);
        let async_fd = |fd: OwnedFd| -> io::Result<AsyncFd<File>> {
            set_nonblocking(fd.as_raw_fd())?;
            register(File::from(fd))
        };
        Ok(Self {
            input: Input {
                fd: Some(async_fd(stdin_tx.into())?),
                pty: false,
            },
            output: Output::Pipes {
                stdout: Some(async_fd(stdout_rx.into())?),
                stderr: Some(async_fd(stderr_rx.into())?),
            },
            waiter,
        })
    }

    /// Applies a `window-change` request.
    pub(crate) fn resize(&self, size: WinSize) {
        if let Output::Pty { master, .. } = &self.output {
            let _ = resize_pty(master.as_raw_fd(), size);
        }
    }

    /// Ends a session that ran to completion: the shell exited and all of
    /// its output was sent. Nothing is signalled, so jobs the shell left
    /// running in the background keep running, as with OpenSSH.
    pub(crate) fn finish(mut self) {
        self.waiter.hangup = false;
    }

    /// Terminates the session (see `Waiter`'s `Drop`).
    pub(crate) fn hangup(self) {
        drop(self);
    }
}

/// Writing side: the pty master or the stdin pipe.
pub(crate) struct Input {
    fd: Option<AsyncFd<File>>,
    pty: bool,
}

impl Input {
    pub(crate) fn is_open(&self) -> bool {
        self.fd.is_some()
    }

    pub(crate) async fn write(&self, data: &[u8]) -> io::Result<usize> {
        let Some(fd) = &self.fd else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        loop {
            let mut guard = fd.writable().await?;
            if let Ok(result) = guard.try_io(|fd| fd.get_ref().write(data)) {
                return result;
            }
        }
    }

    /// Client EOF: close the stdin pipe. A terminal has no EOF of its own (as
    /// with OpenSSH, the client's EOF is not forwarded to a pty).
    pub(crate) fn close(&mut self) {
        if !self.pty {
            self.fd = None;
        }
    }

    /// The process stopped reading (write failed): drop further input.
    pub(crate) fn broken(&mut self) {
        self.fd = None;
    }
}

/// Reading side: the pty master, or stdout and stderr pipes.
pub(crate) enum Output {
    Pty {
        master: AsyncFd<File>,
        draining: bool,
    },
    Pipes {
        stdout: Option<AsyncFd<File>>,
        stderr: Option<AsyncFd<File>>,
    },
}

impl Output {
    /// Reads the next chunk of output into `buf`. Cancel-safe.
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> io::Result<Chunk> {
        match self {
            Self::Pty { master, draining } => loop {
                if *draining {
                    // The shell is gone: take what is buffered, but never
                    // wait, since background jobs may keep the terminal open.
                    return match master.get_ref().read(buf) {
                        Ok(0) => Ok(Chunk::Eof),
                        Ok(n) => Ok(Chunk::Stdout(n)),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock || hung_up(&e) => {
                            Ok(Chunk::Eof)
                        }
                        Err(e) => Err(e),
                    };
                }
                let mut guard = master.readable().await?;
                match guard.try_io(|fd| fd.get_ref().read(buf)) {
                    Ok(Ok(0)) => return Ok(Chunk::Eof),
                    Ok(Ok(n)) => return Ok(Chunk::Stdout(n)),
                    Ok(Err(e)) if hung_up(&e) => return Ok(Chunk::Eof),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => {}
                }
            },
            Self::Pipes { stdout, stderr } => loop {
                if stdout.is_none() && stderr.is_none() {
                    return Ok(Chunk::Eof);
                }
                let (is_stderr, mut guard) = tokio::select! {
                    ready = readable(stdout.as_ref()) => (false, ready?),
                    ready = readable(stderr.as_ref()) => (true, ready?),
                };
                match guard.try_io(|fd| fd.get_ref().read(buf)) {
                    Ok(Ok(0)) => {
                        drop(guard);
                        *(if is_stderr {
                            &mut *stderr
                        } else {
                            &mut *stdout
                        }) = None;
                    }
                    Ok(Ok(n)) if is_stderr => return Ok(Chunk::Stderr(n)),
                    Ok(Ok(n)) => return Ok(Chunk::Stdout(n)),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => {}
                }
            },
        }
    }

    /// The process exited: a terminal is drained without waiting from now on.
    pub(crate) fn exited(&mut self) {
        if let Self::Pty { draining, .. } = self {
            *draining = true;
        }
    }
}

/// Reading the master of a terminal whose slave side is closed fails with EIO.
fn hung_up(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ffi::EIO)
}

async fn readable(fd: Option<&AsyncFd<File>>) -> io::Result<AsyncFdReadyGuard<'_, File>> {
    match fd {
        Some(fd) => fd.readable().await,
        None => std::future::pending().await,
    }
}

/// Waits for the process to exit.
/// Waits for the shell to exit without reaping it, and reaps it when
/// dropped (after hanging the session up, unless it finished).
pub(crate) struct Waiter {
    pid: u32,
    /// A pidfd, readable once the shell has exited. Without one (before
    /// Linux 5.3, or if it cannot be registered) `wait` polls instead.
    exit: Option<AsyncFd<OwnedFd>>,
    /// Hang the process group up when dropped (see `Process::finish`).
    hangup: bool,
}

impl Drop for Waiter {
    /// Hangs up a session that was cut short (the client disconnected or
    /// closed the channel, the connection was dropped, or setting up the
    /// session failed): SIGHUP and SIGCONT to its process group, as a
    /// terminal hang-up would. This also reaches what the shell left behind
    /// after exiting: the shell is reaped only after this, so until then its
    /// PID, the group's ID, cannot have been reused. Then reaps the shell:
    /// now if it has exited, otherwise once it does.
    fn drop(&mut self) {
        let group = c_int::try_from(self.pid)
            .ok()
            .filter(|&pid| pid > 0)
            .and_then(c_int::checked_neg);
        // Only while the shell is still ours to reap: a host that reaps every
        // child (as an init must) may have taken it, and then the group's ID
        // is no longer known to be the session's.
        let ours = exit_code(self.pid).is_ok();
        if let (true, true, Some(group)) = (self.hangup, ours, group) {
            ffi::kill(group, ffi::SIGHUP);
            ffi::kill(group, ffi::SIGCONT);
        }
        if let Ok(false) = reap(self.pid, ffi::WNOHANG) {
            reap_later(self.pid, self.exit.take());
        }
    }
}

/// How often `Waiter::wait` checks for the exit when it has no pidfd.
const EXIT_POLL: Duration = Duration::from_millis(50);

impl Waiter {
    /// Takes charge of a child just started: from now on it is hung up and
    /// reaped when the `Waiter` is dropped. (`std`'s `Child` does neither.)
    fn new(child: std::process::Child) -> Self {
        let pid = child.id();
        let exit = c_int::try_from(pid).ok().and_then(|raw| {
            // SAFETY: pidfd_open takes a PID and flags and returns a new
            // (close-on-exec) descriptor or -1.
            let fd = unsafe { ffi::syscall(ffi::SYS_PIDFD_OPEN, raw, 0 as c_uint) };
            let fd = RawFd::try_from(fd).ok().filter(|&fd| fd >= 0)?;
            // SAFETY: the descriptor is new and nothing else owns it.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // SAFETY: `OwnedFd` keeps its descriptor open and unchanged for
            // the lifetime of the `AsyncFd`.
            unsafe { AsyncFd::register_with_interest(fd, Interest::READABLE) }.ok()
        });
        Self {
            pid,
            exit,
            hangup: true,
        }
    }

    /// Exit code, or 128 + signal number like a shell reports it.
    /// Cancel-safe.
    pub(crate) async fn wait(&mut self) -> io::Result<u32> {
        loop {
            match &self.exit {
                // No system call until the pidfd says the shell has exited.
                Some(fd) => {
                    let mut ready = fd.readable().await?;
                    if let Some(code) = exit_code(self.pid)? {
                        return Ok(code);
                    }
                    ready.clear_ready();
                }
                None => {
                    if let Some(code) = exit_code(self.pid)? {
                        return Ok(code);
                    }
                    tokio::time::sleep(EXIT_POLL).await;
                }
            }
        }
    }
}

/// `waitid` for the exit of the child `pid` with further `options`,
/// retried when a signal interrupts it.
fn wait_child(pid: u32, options: c_int) -> io::Result<ffi::SigInfo> {
    loop {
        let mut info = ffi::SigInfo::default();
        // SAFETY: waitid writes one `siginfo_t` to the pointer.
        let result =
            check(unsafe { ffi::waitid(ffi::P_PID, pid, &raw mut info, ffi::WEXITED | options) });
        match result {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result.map(|_| info),
        }
    }
}

/// Reaps the child `pid` (with `WNOHANG` only if it has exited already);
/// returns whether it did.
fn reap(pid: u32, flags: c_int) -> io::Result<bool> {
    Ok(wait_child(pid, flags)?.pid != 0)
}

/// Reaps the child `pid` once it exits: from a task on the runtime when its
/// pidfd can tell, otherwise (or if the task is dropped first, as when the
/// runtime shuts down) from a thread of its own.
fn reap_later(pid: u32, exit: Option<AsyncFd<OwnedFd>>) {
    let reaper = Reaper { pid, done: false };
    if let (Some(exit), Ok(runtime)) = (exit, tokio::runtime::Handle::try_current()) {
        drop(runtime.spawn(async move {
            // The whole guard, not just the field it sets, belongs to the task.
            let mut reaper = reaper;
            if exit.readable().await.is_ok() {
                reaper.done = matches!(reap(pid, ffi::WNOHANG), Ok(true) | Err(_));
            }
        }));
    }
}

/// The duty to reap a child: dropped before `done`, it hands the child to a
/// thread that waits for it.
struct Reaper {
    pid: u32,
    done: bool,
}

impl Drop for Reaper {
    fn drop(&mut self) {
        if !self.done {
            let pid = self.pid;
            // Without a thread the child stays a zombie: nothing else to do.
            let _ = std::thread::Builder::new().spawn(move || reap(pid, 0));
        }
    }
}

/// The exit code of the child `pid` once it has exited, leaving it
/// unreaped (`WNOWAIT`).
fn exit_code(pid: u32) -> io::Result<Option<u32>> {
    let info = wait_child(pid, ffi::WNOHANG | ffi::WNOWAIT)?;
    let status = u32::try_from(info.status).unwrap_or(255);
    Ok(match (info.pid, info.code) {
        (0, _) => None,
        (_, ffi::CLD_EXITED) => Some(status),
        // Killed (or dumped core) by the signal in `status`.
        _ => Some(status.saturating_add(128)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        broken line\n\
        alice:x:1000:1000:Alice,,,:/home/alice:/usr/bin/zsh\n\
        svc:x:999:999::/nonexistent:\n";

    /// Zero dimensions in a window change keep the current ones.
    #[test]
    fn resize_keeps_unspecified_dimensions() {
        let size = |cols, rows| WinSize {
            cols,
            rows,
            width: 0,
            height: 0,
        };
        let (master, _slave) = open_pty(size(80, 24)).unwrap();
        let fd = master.as_raw_fd();
        let current = || {
            let mut ws = ffi::Winsize::default();
            check(unsafe { ffi::ioctl(fd, ffi::TIOCGWINSZ, &raw mut ws) }).unwrap();
            (ws.cols, ws.rows)
        };
        resize_pty(fd, size(0, 50)).unwrap();
        assert_eq!(current(), (80, 50));
        resize_pty(fd, size(132, 0)).unwrap();
        assert_eq!(current(), (132, 50));
        resize_pty(fd, size(0, 0)).unwrap();
        assert_eq!(current(), (132, 50));
    }

    /// A shell still running when its session ends is reaped once it exits,
    /// even if the runtime that was to do it is gone by then.
    #[test]
    fn reaping_outlives_the_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let pid = runtime.block_on(async {
            let mut waiter = Waiter::new(Command::new("sleep").arg("0.2").spawn().unwrap());
            assert!(waiter.exit.is_some(), "no pidfd");
            waiter.hangup = false;
            let pid = waiter.pid;
            drop(waiter);
            pid
        });
        drop(runtime);
        let gone = || !Path::new(&format!("/proc/{pid}")).exists();
        for _ in 0..300 {
            if gone() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the child was not reaped");
    }

    /// A shell that something else reaped (an init's `waitpid(-1)`) is no
    /// longer known to lead its group, so the group is not signalled.
    #[test]
    fn groups_of_shells_reaped_elsewhere_are_left_alone() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let leader = Command::new("sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .unwrap();
            let group = leader.id();
            let mut member = Command::new("sleep")
                .arg("30")
                .process_group(i32::try_from(group).unwrap())
                .spawn()
                .unwrap();
            let waiter = Waiter::new(leader);
            assert!(waiter.hangup);
            // The host reaps the shell behind tinyssh's back.
            ffi::kill(i32::try_from(group).unwrap(), 9);
            let mut info = ffi::SigInfo::default();
            check(unsafe { ffi::waitid(ffi::P_PID, group, &raw mut info, ffi::WEXITED) }).unwrap();
            drop(waiter);
            std::thread::sleep(Duration::from_millis(100));
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", member.id())).unwrap();
            let alive = !stat
                .rsplit_once(')')
                .unwrap()
                .1
                .trim_start()
                .starts_with('Z');
            member.kill().unwrap();
            member.wait().unwrap();
            assert!(alive, "the group was signalled");
        });
    }

    #[test]
    fn passwd_lookup_by_name_and_uid() {
        let alice = find_account(PASSWD, |name, _| name == "alice").unwrap();
        assert_eq!((alice.uid, alice.gid), (1000, 1000));
        assert_eq!(
            (alice.home.as_str(), alice.shell.as_str()),
            ("/home/alice", "/usr/bin/zsh")
        );
        let svc = find_account(PASSWD, |_, uid| uid == 999).unwrap();
        assert_eq!((svc.name.as_str(), svc.shell.as_str()), ("svc", ""));
        assert!(find_account(PASSWD, |name, _| name == "mallory").is_none());
    }

    #[test]
    fn supplementary_groups() {
        let group = "alice:x:1000:\nwheel:x:10:bob,alice\naudio:x:29:alice\nbad\nvideo:x:44:bob\n";
        assert_eq!(find_groups(group, "alice", 1000), [1000, 10, 29]);
    }

    #[test]
    fn exec_flag_matches_the_shell() {
        assert_eq!(command_flag("/bin/sh"), "-c");
        assert_eq!(command_flag(r"C:\Windows\System32\cmd.exe"), "/c");
        assert_eq!(command_flag("pwsh.exe"), "-c");
    }
}
