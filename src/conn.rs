//! The sans-IO server connection: transport (RFC 4253), user authentication
//! (RFC 4252) and one session channel (RFC 4254).
//!
//! Memory: every buffer lives in an [`Arena`] allocated once per connection.
//! Received packets are decrypted in place and parsed as borrowed slices;
//! replies are built, padded and encrypted directly in the send buffer.
//!
//! Flow control: the receive window granted to the client never exceeds the
//! free space of the stdin buffer, so incoming data can always be accepted
//! without blocking the connection (which would deadlock on a full terminal).
//! Process output is only taken when the client's window and the send buffer
//! have room for it.

use crate::kex::{self, Ephemeral, Role};
use crate::keys::PublicKey;
use crate::sha256::Sha256;
use crate::transport::{Keys, OVERHEAD, RxBuf, TxBuf};
use crate::wire::{Buf, Hash, Msg, Put, Res, msg, reason};
use crate::{Config, Error, VERSION, rng};
use core::ops::Range;

const RX_LEN: usize = 128 * 1024;
const TX_LEN: usize = 256 * 1024;
const DEFER_LEN: usize = 4096;
const DEFER_MAX: usize = 32;
/// Largest CHANNEL_DATA payload, both directions.
const MAX_DATA: u32 = 32 * 1024;
/// Re-exchanges a client may start before it authenticates. RFC 4253 allows
/// them at any time, but no client needs many; the cap bounds the key
/// exchange work an unauthenticated peer can cause.
const MAX_PREAUTH_REKEYS: u32 = 4;
const MAX_DATA_LEN: usize = 32 * 1024;
/// Most process output taken at once (one read system call); it is sent as
/// several packets, written to the socket together.
const OUTPUT_BATCH: usize = 128 * 1024;
/// Send-buffer space kept for control messages: incoming packets are only
/// processed while this much is free, and channel data never uses it.
const RESERVE: usize = 16 * 1024;
/// Upper bound for the payload of any control message we send.
const CONTROL_MAX: usize = 1024;
/// Message, channel, data type and length fields of CHANNEL_EXTENDED_DATA.
const DATA_HEADER: usize = 1 + 4 + 4 + 4;
const USER_MAX: usize = 64;
const TERM_MAX: usize = 64;
/// Rekey before 2^31 packets so sequence numbers never wrap within one key.
const REKEY_PACKETS: u64 = 1 << 31;

/// Terminal size in characters and pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WinSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// Width in pixels (0 if unknown).
    pub width: u16,
    /// Height in pixels (0 if unknown).
    pub height: u16,
}

impl WinSize {
    /// This size changed as `request` asks: its zero dimensions are
    /// unspecified (RFC 4254 §6.2) and keep these.
    pub(crate) fn apply(self, request: Self) -> Self {
        let pick = |new: u16, old: u16| if new == 0 { old } else { new };
        Self {
            cols: pick(request.cols, self.cols),
            rows: pick(request.rows, self.rows),
            width: pick(request.width, self.width),
            height: pick(request.height, self.height),
        }
    }

    fn read(m: &mut Msg<'_>) -> Result<Self, Error> {
        let clamp = |v: u32| u16::try_from(v).unwrap_or(u16::MAX);
        Ok(Self {
            cols: clamp(m.u32()?),
            rows: clamp(m.u32()?),
            width: clamp(m.u32()?),
            height: clamp(m.u32()?),
        })
    }
}

/// A pseudo-terminal requested with `pty-req`.
#[derive(Clone, Copy, Debug)]
pub struct Pty<'a> {
    /// The client's `$TERM`.
    pub term: &'a str,
    /// Initial terminal size.
    pub size: WinSize,
}

/// The process requested for the session channel.
#[derive(Debug)]
pub struct SpawnRequest<'a> {
    /// The authenticated user name.
    pub user: &'a str,
    /// The `exec` command, or `None` for an interactive login shell.
    pub command: Option<&'a [u8]>,
    /// Pseudo-terminal parameters, if the client requested one.
    pub pty: Option<Pty<'a>>,
}

/// Something the driver has to act on.
#[derive(Debug)]
pub enum Event<'a> {
    /// Start the session's process. The request was already acknowledged; if
    /// the process cannot be started, report it with [`Connection::output`]
    /// and [`Connection::exited`].
    Spawn(SpawnRequest<'a>),
    /// The client's terminal was resized.
    Resize(WinSize),
    /// The client closed the session: terminate the process if it is running.
    Hangup,
}

/// All memory one connection needs, allocated once when it is accepted.
pub struct Arena {
    mem: Box<[u8]>,
    window: usize,
}

impl Arena {
    /// Allocates the buffers for one connection using `config.window_size`.
    pub fn new(config: &Config) -> Self {
        let window = usize::try_from(config.window_size)
            .unwrap_or(usize::MAX)
            .clamp(MAX_DATA_LEN, 1 << 30);
        let len = [RX_LEN, TX_LEN, DEFER_LEN, window, OUTPUT_BATCH]
            .iter()
            .fold(0usize, |sum, n| sum.saturating_add(*n));
        Self {
            mem: vec![0; len].into_boxed_slice(),
            window,
        }
    }

    /// Carves the arena into the connection's [`Memory`] and a scratch buffer
    /// for process output on its way to [`Connection::output`] (as large as
    /// the most [`Connection::output_room`] ever allows).
    pub fn split(&mut self) -> (Memory<'_>, &mut [u8]) {
        let mut rest: &mut [u8] = &mut self.mem;
        let rx = carve(&mut rest, RX_LEN);
        let tx = carve(&mut rest, TX_LEN);
        let defer = carve(&mut rest, DEFER_LEN);
        let ring = carve(&mut rest, self.window);
        (
            Memory {
                rx,
                tx,
                defer,
                ring,
            },
            rest,
        )
    }
}

fn carve<'a>(rest: &mut &'a mut [u8], n: usize) -> &'a mut [u8] {
    let all = core::mem::take(rest);
    let at = n.min(all.len());
    let (head, tail) = all.split_at_mut(at);
    *rest = tail;
    head
}

/// The protocol buffers of one connection (see [`Arena::split`]).
pub struct Memory<'a> {
    rx: &'a mut [u8],
    tx: &'a mut [u8],
    defer: &'a mut [u8],
    ring: &'a mut [u8],
}

/// A sans-IO SSH server connection.
///
/// Drive it by copying socket input into [`read_buf`](Self::read_buf),
/// calling [`poll`](Self::poll) until it returns `Ok(None)`, and writing
/// [`write_buf`](Self::write_buf) to the socket. Session data flows through
/// [`stdin`](Self::stdin), [`output`](Self::output) and
/// [`exited`](Self::exited). Any `Err` is final: flush `write_buf` (it may
/// hold a `SSH_MSG_DISCONNECT`) and drop the connection.
pub struct Connection<'a> {
    rx: RxBuf<'a>,
    rx_keys: Keys,
    core: Core<'a>,
}

/// Something `poll` must report, recorded without borrowing.
enum Pending {
    Spawn(Option<Range<usize>>),
    Resize(WinSize),
    Hangup,
}

impl<'a> Connection<'a> {
    /// Starts a connection: queues our identification line and KEXINIT.
    pub fn new(config: &'a Config, mem: Memory<'a>) -> Result<Self, Error> {
        let mut core = Core {
            cfg: config,
            tx: TxBuf::new(mem.tx),
            tx_keys: Keys::new(),
            defer: Defer {
                buf: mem.defer,
                len: 0,
                count: 0,
            },
            ring: Ring {
                buf: mem.ring,
                head: 0,
                len: 0,
            },
            peer_version: [0; 255],
            peer_version_len: 0,
            version_done: false,
            kex: Kex::Idle,
            session_id: None,
            strict: false,
            skip_next: false,
            received: 0,
            auth: Auth::Kex,
            failures: 0,
            preauth_rekeys: 0,
            user: [0; USER_MAX],
            user_len: 0,
            chan: Channel::closed(),
            next_id: 0,
            closed: false,
        };
        core.tx.raw(VERSION.as_bytes())?;
        core.tx.raw(b"\r\n")?;
        core.send_kexinit(true)?;
        Ok(Self {
            rx: RxBuf::new(mem.rx),
            rx_keys: Keys::new(),
            core,
        })
    }

    /// Whether socket input can be accepted (see [`read_buf`](Self::read_buf)).
    pub fn wants_read(&self) -> bool {
        !self.core.closed && self.rx.has_space()
    }

    /// Buffer to read socket bytes into; report them with
    /// [`read_done`](Self::read_done).
    pub fn read_buf(&mut self) -> &mut [u8] {
        match self.core.closed {
            true => &mut [],
            false => self.rx.space(),
        }
    }

    /// Records `n` bytes read into [`read_buf`](Self::read_buf).
    pub fn read_done(&mut self, n: usize) {
        self.rx.filled(n);
    }

    /// Bytes waiting to be written to the socket.
    pub fn write_buf(&self) -> &[u8] {
        self.core.tx.pending()
    }

    /// Records that `n` bytes of [`write_buf`](Self::write_buf) were written.
    pub fn write_done(&mut self, n: usize) {
        self.core.tx.advance(n);
    }

    /// Whether the connection is finished; close the socket once
    /// [`write_buf`](Self::write_buf) is empty.
    pub fn is_closed(&self) -> bool {
        self.core.closed
    }

    /// Whether the client has authenticated.
    pub fn is_authenticated(&self) -> bool {
        self.core.auth == Auth::Done
    }

    /// The authenticated user, if any.
    pub fn user(&self) -> Option<&str> {
        self.is_authenticated().then(|| self.core.user())
    }

    /// Processes buffered input until an event occurs or more input (or
    /// send-buffer space) is needed.
    pub fn poll(&mut self) -> Result<Option<Event<'_>>, Error> {
        match self.step() {
            Ok(Some(pending)) => Ok(Some(self.event(pending))),
            Ok(None) => Ok(None),
            Err(e) => {
                self.core.fail(&e);
                Err(e)
            }
        }
    }

    fn step(&mut self) -> Result<Option<Pending>, Error> {
        loop {
            if self.core.closed || self.core.tx.free() < RESERVE {
                return Ok(None);
            }
            if !self.core.version_done {
                let Some(line) = self.rx.line()? else {
                    return Ok(None);
                };
                self.core.set_version(self.rx.get(line))?;
                continue;
            }
            let Some(range) = self.rx.packet(&mut self.rx_keys)? else {
                return Ok(None);
            };
            let base = range.start;
            let pending = self
                .core
                .dispatch(&mut self.rx_keys, self.rx.get(range), base)?;
            self.core.pump()?;
            self.core.maybe_rekey(&self.rx_keys)?;
            if pending.is_some() {
                return Ok(pending);
            }
        }
    }

    fn event(&self, pending: Pending) -> Event<'_> {
        match pending {
            Pending::Spawn(command) => Event::Spawn(SpawnRequest {
                user: self.core.user(),
                command: command.map(|range| self.rx.get(range)),
                pty: self.core.chan.pty.then(|| Pty {
                    term: self.core.chan.term(),
                    size: self.core.chan.size,
                }),
            }),
            Pending::Resize(size) => Event::Resize(size),
            Pending::Hangup => Event::Hangup,
        }
    }

    /// Client input waiting to be written to the process (one contiguous
    /// piece; call again after [`stdin_consumed`](Self::stdin_consumed)).
    pub fn stdin(&self) -> &[u8] {
        self.core.ring.front()
    }

    /// Records that `n` bytes of [`stdin`](Self::stdin) reached the process.
    pub fn stdin_consumed(&mut self, n: usize) -> Result<(), Error> {
        self.core.ring.consume(n);
        self.after_local()
    }

    /// Whether the client sent EOF and all of its input was consumed: close
    /// the process's stdin.
    pub fn stdin_closed(&self) -> bool {
        let c = &self.core.chan;
        c.open && c.eof_in && self.core.ring.is_empty()
    }

    /// How many bytes of process output [`output`](Self::output) accepts now.
    /// Zero while a key exchange is in flight or the client's window is full.
    pub fn output_room(&self) -> usize {
        let core = &self.core;
        let c = &core.chan;
        if core.closed
            || core.tx_paused()
            || !c.open
            || !c.started
            || c.eof_out
            || c.close_out
            || c.close_in
        {
            return 0;
        }
        let packet = core.chan.packet_limit();
        // Each packet of up to `packet` data bytes costs `framing` more.
        let framing = OVERHEAD + DATA_HEADER;
        let per_packet = packet.saturating_add(framing);
        let free = core.tx.free().saturating_sub(RESERVE);
        let full = free.checked_div(per_packet).unwrap_or_default();
        let rest = free.checked_rem(per_packet).unwrap_or_default();
        let tx = full
            .saturating_mul(packet)
            .saturating_add(rest.saturating_sub(framing));
        let window = usize::try_from(c.send_window).unwrap_or(usize::MAX);
        window.min(OUTPUT_BATCH).min(tx)
    }

    /// Sends process output (at most [`output_room`](Self::output_room)
    /// bytes) as `stdout`, or as `stderr` extended data, split into as many
    /// packets as the client's maximum packet size requires.
    pub fn output(&mut self, stderr: bool, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > self.output_room() {
            return Err(Error::Protocol("output exceeds output_room()"));
        }
        let core = &mut self.core;
        let peer = core.chan.peer;
        // Not zero: output_room() would have been zero.
        let packet = core.chan.packet_limit().max(1);
        for chunk in data.chunks(packet) {
            core.tx.packet(
                &mut core.tx_keys,
                chunk.len().saturating_add(DATA_HEADER),
                |w| {
                    match stderr {
                        true => {
                            w.put_u8(msg::CHANNEL_EXTENDED_DATA)?;
                            w.put_u32(peer)?;
                            w.put_u32(1)?;
                        }
                        false => {
                            w.put_u8(msg::CHANNEL_DATA)?;
                            w.put_u32(peer)?;
                        }
                    }
                    w.put_string(chunk)
                },
            )?;
        }
        let sent = u32::try_from(data.len()).unwrap_or(u32::MAX);
        core.chan.send_window = core.chan.send_window.saturating_sub(sent);
        self.after_local()
    }

    /// Reports that the process exited after all of its output was passed to
    /// [`output`](Self::output): sends `exit-status`, EOF and CLOSE.
    pub fn exited(&mut self, code: u32) -> Result<(), Error> {
        let c = &mut self.core.chan;
        if c.open && c.started && !c.close_out && c.exit.is_none() {
            c.exit = Some(code);
        }
        self.after_local()
    }

    /// Starts a server-initiated key exchange right away.
    #[cfg(test)]
    pub(crate) fn force_rekey(&mut self) -> Result<(), Error> {
        self.core.send_kexinit(false)
    }

    fn after_local(&mut self) -> Result<(), Error> {
        let result = self
            .core
            .pump()
            .and_then(|()| self.core.maybe_rekey(&self.rx_keys));
        if let Err(e) = &result {
            self.core.fail(e);
        }
        result
    }
}

/// Key exchange progress (RFC 4253 §7).
// Boxing the pending keys would allocate on every rekey.
#[allow(clippy::large_enum_variant)]
enum Kex {
    Idle,
    /// We sent KEXINIT; waiting for the peer's.
    Sent {
        cookie: [u8; 16],
    },
    /// Both KEXINITs seen (H started); waiting for KEX_ECDH_INIT.
    AwaitInit {
        hash: Sha256,
    },
    /// We sent KEX_ECDH_REPLY and NEWKEYS; waiting for the peer's NEWKEYS.
    AwaitNewKeys {
        /// Always `Some`; an `Option` so it can be swapped into place.
        next: Option<crate::cipher::Aead>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Auth {
    /// Initial key exchange not finished.
    Kex,
    /// Waiting for SERVICE_REQUEST "ssh-userauth".
    Service,
    Userauth,
    Done,
}

struct Channel {
    open: bool,
    id: u32,
    peer: u32,
    /// What we may still send.
    send_window: u32,
    send_max: u32,
    /// What the client may still send.
    recv_window: u32,
    pty: bool,
    term: [u8; TERM_MAX],
    term_len: usize,
    size: WinSize,
    started: bool,
    eof_in: bool,
    close_in: bool,
    exit: Option<u32>,
    eof_out: bool,
    close_out: bool,
}

impl Channel {
    const fn closed() -> Self {
        Self {
            open: false,
            id: 0,
            peer: 0,
            send_window: 0,
            send_max: 0,
            recv_window: 0,
            pty: false,
            term: [0; TERM_MAX],
            term_len: 0,
            size: WinSize {
                cols: 0,
                rows: 0,
                width: 0,
                height: 0,
            },
            started: false,
            eof_in: false,
            close_in: false,
            exit: None,
            eof_out: false,
            close_out: false,
        }
    }

    /// Most data bytes in one CHANNEL_DATA packet to the client.
    fn packet_limit(&self) -> usize {
        usize::try_from(self.send_max)
            .unwrap_or(usize::MAX)
            .min(MAX_DATA_LEN)
    }

    fn term(&self) -> &str {
        core::str::from_utf8(self.term.get(..self.term_len).unwrap_or_default()).unwrap_or_default()
    }
}

struct Core<'a> {
    cfg: &'a Config,
    tx: TxBuf<'a>,
    tx_keys: Keys,
    defer: Defer<'a>,
    ring: Ring<'a>,
    peer_version: [u8; 255],
    peer_version_len: usize,
    version_done: bool,
    kex: Kex,
    session_id: Option<[u8; 32]>,
    strict: bool,
    /// The peer's guessed KEX packet must be ignored.
    skip_next: bool,
    received: u64,
    auth: Auth,
    failures: u32,
    /// Re-exchanges the peer started before authenticating.
    preauth_rekeys: u32,
    user: [u8; USER_MAX],
    user_len: usize,
    chan: Channel,
    next_id: u32,
    closed: bool,
}

impl Core<'_> {
    /// Between our KEXINIT and our NEWKEYS only transport and KEX messages
    /// may be sent (RFC 4253 §7.1).
    fn tx_paused(&self) -> bool {
        matches!(self.kex, Kex::Sent { .. } | Kex::AwaitInit { .. })
    }

    fn user(&self) -> &str {
        core::str::from_utf8(self.user.get(..self.user_len).unwrap_or_default()).unwrap_or_default()
    }

    fn peer_version(&self) -> &[u8] {
        self.peer_version
            .get(..self.peer_version_len)
            .unwrap_or_default()
    }

    /// Sends a message, or queues it until NEWKEYS while our KEXINIT is
    /// outstanding.
    fn send(&mut self, ty: u8, body: impl FnOnce(&mut Buf<'_>) -> Res) -> Result<(), Error> {
        let immediate = matches!(ty, msg::DISCONNECT..=msg::DEBUG | msg::KEXINIT..=49);
        if self.tx_paused() && !immediate {
            return self.defer.push(ty, body);
        }
        self.tx.packet(&mut self.tx_keys, CONTROL_MAX, |w| {
            w.put_u8(ty)?;
            body(w)
        })
    }

    fn send_kexinit(&mut self, initial: bool) -> Result<(), Error> {
        let cookie = rng::array::<16>()?;
        self.tx.packet(&mut self.tx_keys, CONTROL_MAX, |w| {
            kex::write_kexinit(w, &cookie, Role::Server, initial)
        })?;
        self.kex = Kex::Sent { cookie };
        Ok(())
    }

    fn disconnect(&mut self, code: u32, text: &str) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.tx.packet(&mut self.tx_keys, CONTROL_MAX, |w| {
            w.put_u8(msg::DISCONNECT)?;
            w.put_u32(code)?;
            w.put_string(text.as_bytes())?;
            w.put_string(b"")
        });
    }

    fn fail(&mut self, e: &Error) {
        match e {
            Error::Mac => self.disconnect(reason::MAC_ERROR, "message authentication failed"),
            Error::Protocol(text) => self.disconnect(reason::PROTOCOL_ERROR, text),
            Error::Disconnected => self.closed = true,
            _ => self.disconnect(reason::BY_APPLICATION, "internal error"),
        }
    }

    fn set_version(&mut self, line: &[u8]) -> Result<(), Error> {
        // RFC 4253 §4.2: printable US-ASCII and spaces only.
        if !line.starts_with(b"SSH-2.0-") || !line.iter().all(|&b| (b' '..=b'~').contains(&b)) {
            return Err(Error::Protocol("unsupported protocol version"));
        }
        let dst = self.peer_version.get_mut(..line.len());
        dst.ok_or(Error::Protocol("identification line too long"))?
            .copy_from_slice(line);
        self.peer_version_len = line.len();
        self.version_done = true;
        Ok(())
    }

    fn dispatch(
        &mut self,
        rx: &mut Keys,
        payload: &[u8],
        base: usize,
    ) -> Result<Option<Pending>, Error> {
        self.received = self.received.saturating_add(1);
        let mut m = Msg::new(payload);
        let ty = m.u8()?;
        if ty == msg::DISCONNECT {
            self.closed = true;
            return Err(Error::Disconnected);
        }
        if core::mem::take(&mut self.skip_next) {
            return Ok(None);
        }
        if !matches!(ty, msg::KEXINIT | msg::NEWKEYS | msg::KEX_ECDH_INIT) {
            let initial = self.auth == Auth::Kex;
            let peer_in_kex = matches!(self.kex, Kex::AwaitInit { .. } | Kex::AwaitNewKeys { .. });
            let generic = matches!(ty, msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED);
            // Strict KEX forbids even IGNORE/DEBUG during the first exchange.
            let allowed = generic && !(initial && self.strict);
            if (initial || peer_in_kex) && !allowed {
                return Err(Error::Protocol("unexpected message during key exchange"));
            }
        }
        let none = |r: Result<(), Error>| r.map(|()| None);
        match ty {
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => Ok(None),
            msg::KEXINIT => none(self.on_kexinit(payload)),
            msg::KEX_ECDH_INIT => none(self.on_ecdh_init(m)),
            msg::NEWKEYS => none(self.on_newkeys(rx)),
            msg::SERVICE_REQUEST => none(self.on_service_request(m)),
            msg::USERAUTH_REQUEST => none(self.on_userauth(m, payload)),
            msg::GLOBAL_REQUEST..=127 if self.auth != Auth::Done => {
                Err(Error::Protocol("connection message before authentication"))
            }
            msg::GLOBAL_REQUEST => {
                m.string()?;
                match m.bool()? {
                    true => none(self.send(msg::REQUEST_FAILURE, |_| Ok(()))),
                    false => Ok(None),
                }
            }
            msg::CHANNEL_OPEN => none(self.on_open(m)),
            msg::CHANNEL_WINDOW_ADJUST..=msg::CHANNEL_REQUEST => {
                let id = m.u32()?;
                match self.chan.open && id == self.chan.id {
                    true => self.on_channel(ty, m, payload, base),
                    // Late message for a channel that is already gone.
                    false => Ok(None),
                }
            }
            // Replies to requests we never make.
            81 | 82 | 91 | 92 | 99 | 100 => Ok(None),
            _ => {
                let seq = rx.seq.wrapping_sub(1);
                none(self.send(msg::UNIMPLEMENTED, |w| w.put_u32(seq)))
            }
        }
    }

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<(), Error> {
        let initial = self.session_id.is_none();
        if matches!(self.kex, Kex::Idle) {
            if self.auth != Auth::Done {
                self.preauth_rekeys = self.preauth_rekeys.saturating_add(1);
                if self.preauth_rekeys > MAX_PREAUTH_REKEYS {
                    return Err(Error::Protocol(
                        "too many key re-exchanges before authentication",
                    ));
                }
            }
            // The peer starts a re-exchange: answer with our KEXINIT first.
            self.send_kexinit(false)?;
        }
        let Kex::Sent { cookie } = self.kex else {
            return Err(Error::Protocol("unexpected KEXINIT"));
        };
        let peer = kex::negotiate(payload, Role::Server, initial).inspect_err(|e| {
            if let Error::Protocol(text) = e {
                self.disconnect(reason::KEY_EXCHANGE_FAILED, text);
            }
        })?;
        if initial {
            self.strict = peer.strict;
            if self.strict && self.received != 1 {
                return Err(Error::Protocol(
                    "strict KEX: KEXINIT was not the first packet",
                ));
            }
        }
        self.skip_next = peer.wrong_guess;
        let mut hash = Sha256::new();
        let host = self.cfg.host_key.public_key().blob();
        let res: Res = (|| {
            let mut w = Hash(&mut hash);
            w.put_string(self.peer_version())?;
            w.put_string(VERSION.as_bytes())?;
            w.put_string(payload)?;
            kex::put_kexinit_string(&mut w, &cookie, Role::Server, initial)?;
            w.put_string(&host)
        })();
        res.map_err(|_| Error::Protocol("exchange hash"))?;
        self.kex = Kex::AwaitInit { hash };
        Ok(())
    }

    fn on_ecdh_init(&mut self, mut m: Msg<'_>) -> Result<(), Error> {
        let hash = match core::mem::replace(&mut self.kex, Kex::Idle) {
            Kex::AwaitInit { hash } => hash,
            _ => return Err(Error::Protocol("unexpected KEX_ECDH_INIT")),
        };
        let q_c = m.fixed_string::<32>()?;
        m.end()?;
        let (q_s, k) = Ephemeral::exchange(&q_c)?;
        let h = kex::finish_hash(hash, &q_c, &q_s, &k)?;
        let session_id = *self.session_id.get_or_insert(h);
        let signature = self.cfg.host_key.sign(&h);
        let host = self.cfg.host_key.public_key().blob();
        self.send(msg::KEX_ECDH_REPLY, |w| {
            w.put_string(&host)?;
            w.put_string(&q_s)?;
            w.put_string(&signature)
        })?;
        self.send(msg::NEWKEYS, |_| Ok(()))?;
        let (client_to_server, server_to_client) = kex::derive_keys(&k, &h, &session_id)?;
        self.tx_keys.install(server_to_client, self.strict);
        self.kex = Kex::AwaitNewKeys {
            next: Some(client_to_server),
        };
        // Replies held back during the exchange go out under the new keys.
        self.defer.flush(&mut self.tx, &mut self.tx_keys)
    }

    fn on_newkeys(&mut self, rx: &mut Keys) -> Result<(), Error> {
        let Kex::AwaitNewKeys { next } = &mut self.kex else {
            return Err(Error::Protocol("unexpected NEWKEYS"));
        };
        // Swapped in, so that no copy of the new keys stays behind; the old
        // ones are wiped when `next` is dropped in place.
        rx.install_swap(next, self.strict);
        self.kex = Kex::Idle;
        if self.auth == Auth::Kex {
            self.auth = Auth::Service;
        }
        Ok(())
    }

    fn maybe_rekey(&mut self, rx: &Keys) -> Result<(), Error> {
        if self.closed || self.auth == Auth::Kex || !matches!(self.kex, Kex::Idle) {
            return Ok(());
        }
        let limit = self.cfg.rekey_limit.max(1);
        let tx = &self.tx_keys;
        if tx.bytes >= limit
            || rx.bytes >= limit
            || tx.packets >= REKEY_PACKETS
            || rx.packets >= REKEY_PACKETS
        {
            self.send_kexinit(false)?;
        }
        Ok(())
    }

    fn on_service_request(&mut self, mut m: Msg<'_>) -> Result<(), Error> {
        let service = m.string()?;
        if self.auth != Auth::Service || service != b"ssh-userauth" {
            self.disconnect(reason::SERVICE_NOT_AVAILABLE, "service not available");
            return Err(Error::Protocol("service not available"));
        }
        self.auth = Auth::Userauth;
        self.send(msg::SERVICE_ACCEPT, |w| w.put_string(b"ssh-userauth"))
    }

    fn on_userauth(&mut self, mut m: Msg<'_>, payload: &[u8]) -> Result<(), Error> {
        match self.auth {
            // RFC 4252 §5.1: requests after success are ignored.
            Auth::Done => return Ok(()),
            Auth::Userauth => {}
            _ => return Err(Error::Protocol("unexpected USERAUTH_REQUEST")),
        }
        let user = m.string()?;
        let service = m.string()?;
        let method = m.string()?;
        let user = core::str::from_utf8(user)
            .ok()
            .filter(|u| !u.is_empty() && u.len() <= USER_MAX);
        if let (b"publickey", b"ssh-connection", Some(user)) = (method, service, user) {
            let signed = m.bool()?;
            let alg = m.string()?;
            let blob = m.string()?;
            // Signed data: string(session id) || this payload up to the signature.
            let signed_len = m.offset_in(payload);
            let signature = match signed {
                true => Some(m.string()?),
                false => None,
            };
            m.end()?;
            let key = (alg == kex::HOST_KEY_ALG)
                .then(|| PublicKey::from_blob(blob))
                .flatten();
            if let Some(key) = key
                && self.cfg.authorizer.authorize(user, &key)
            {
                let Some(signature) = signature else {
                    return self.send(msg::USERAUTH_PK_OK, |w| {
                        w.put_string(alg)?;
                        w.put_string(blob)
                    });
                };
                let session_id = self.session_id.unwrap_or_default();
                let id_len = 32u32.to_be_bytes();
                let request = payload.get(..signed_len).unwrap_or_default();
                if key.verify(&[&id_len, &session_id, request], signature) {
                    if let Some(dst) = self.user.get_mut(..user.len()) {
                        dst.copy_from_slice(user.as_bytes());
                        self.user_len = user.len();
                    }
                    self.auth = Auth::Done;
                    return self.send(msg::USERAUTH_SUCCESS, |_| Ok(()));
                }
            }
        }
        if method != b"none" {
            self.failures = self.failures.saturating_add(1);
        }
        self.send(msg::USERAUTH_FAILURE, |w| {
            w.put_string(b"publickey")?;
            w.put_bool(false)
        })?;
        if self.failures >= self.cfg.max_auth_attempts {
            self.disconnect(
                reason::NO_MORE_AUTH_METHODS,
                "too many authentication failures",
            );
            return Err(Error::Protocol("too many authentication failures"));
        }
        Ok(())
    }

    fn on_open(&mut self, mut m: Msg<'_>) -> Result<(), Error> {
        let kind = m.string()?;
        let peer = m.u32()?;
        let window = m.u32()?;
        let max_packet = m.u32()?;
        let refusal = match (kind, self.chan.open) {
            (b"session", true) => Some((1, "only one session at a time")),
            // No data could ever be sent.
            (b"session", false) if max_packet == 0 => Some((1, "maximum packet size of zero")),
            (b"session", false) => None,
            _ => Some((3, "only session channels are supported")),
        };
        if let Some((code, text)) = refusal {
            return self.send(msg::CHANNEL_OPEN_FAILURE, |w| {
                w.put_u32(peer)?;
                w.put_u32(code)?;
                w.put_string(text.as_bytes())?;
                w.put_string(b"")
            });
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        let recv_window = u32::try_from(self.ring.capacity()).unwrap_or(u32::MAX);
        self.ring.clear();
        self.chan = Channel {
            open: true,
            id,
            peer,
            send_window: window,
            send_max: max_packet,
            recv_window,
            ..Channel::closed()
        };
        self.send(msg::CHANNEL_OPEN_CONFIRMATION, |w| {
            w.put_u32(peer)?;
            w.put_u32(id)?;
            w.put_u32(recv_window)?;
            w.put_u32(MAX_DATA)
        })
    }

    fn on_channel(
        &mut self,
        ty: u8,
        mut m: Msg<'_>,
        payload: &[u8],
        base: usize,
    ) -> Result<Option<Pending>, Error> {
        let c = &mut self.chan;
        // RFC 4254 §5.3: nothing may follow the peer's CHANNEL_CLOSE.
        if c.close_in {
            return Ok(None);
        }
        match ty {
            msg::CHANNEL_WINDOW_ADJUST => {
                c.send_window = c.send_window.saturating_add(m.u32()?);
                Ok(None)
            }
            msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
                let extended = ty == msg::CHANNEL_EXTENDED_DATA;
                if extended {
                    m.u32()?; // data type code
                }
                let data = m.string()?;
                if c.eof_in {
                    return Ok(None);
                }
                let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
                if len > c.recv_window {
                    return Err(Error::Protocol("channel window exceeded"));
                }
                // Extended data from a client means nothing to a session and
                // is dropped, but it still consumes window (RFC 4254 §5.2).
                // Taking no buffer space, it is granted back by `pump`.
                // recv_window <= ring free space, so a push within it fits.
                if !extended && !self.ring.push(data) {
                    return Err(Error::Protocol("channel window exceeded"));
                }
                c.recv_window = c.recv_window.saturating_sub(len);
                Ok(None)
            }
            msg::CHANNEL_EOF => {
                c.eof_in = true;
                Ok(None)
            }
            msg::CHANNEL_CLOSE => {
                c.close_in = true;
                Ok(Some(Pending::Hangup))
            }
            _ => self.on_request(m, payload, base),
        }
    }

    fn on_request(
        &mut self,
        mut m: Msg<'_>,
        payload: &[u8],
        base: usize,
    ) -> Result<Option<Pending>, Error> {
        // After our CHANNEL_CLOSE nothing more may be sent on the channel,
        // replies included, and the session is over anyway.
        if self.chan.close_out {
            return Ok(None);
        }
        let kind = m.string()?;
        let want_reply = m.bool()?;
        let c = &mut self.chan;
        let (ok, pending) = match kind {
            b"pty-req" if !c.started => {
                let term = m.string()?;
                let size = WinSize::read(&mut m)?;
                m.string()?; // encoded terminal modes: the pty defaults are used
                let dst = c
                    .term
                    .get_mut(..term.len())
                    .filter(|_| term.iter().all(u8::is_ascii_graphic));
                let ok = dst.map(|dst| dst.copy_from_slice(term)).is_some();
                if ok {
                    c.pty = true;
                    c.term_len = term.len();
                    c.size = size;
                }
                (ok, None)
            }
            b"shell" if !c.started => {
                c.started = true;
                (true, Some(Pending::Spawn(None)))
            }
            b"exec" if !c.started => {
                let at = base.saturating_add(m.offset_in(payload)).saturating_add(4);
                let command = m.string()?;
                // A NUL would end the command early on Windows.
                match command.contains(&0) {
                    true => (false, None),
                    false => {
                        c.started = true;
                        let range = at..at.saturating_add(command.len());
                        (true, Some(Pending::Spawn(Some(range))))
                    }
                }
            }
            b"window-change" => {
                // Before the shell starts this updates the size it will get;
                // afterwards the platform applies it to the terminal's size.
                let size = WinSize::read(&mut m)?;
                c.size = c.size.apply(size);
                (true, (c.started && c.pty).then_some(Pending::Resize(size)))
            }
            _ => (false, None),
        };
        if want_reply {
            let peer = c.peer;
            let ty = if ok {
                msg::CHANNEL_SUCCESS
            } else {
                msg::CHANNEL_FAILURE
            };
            self.send(ty, |w| w.put_u32(peer))?;
        }
        Ok(pending)
    }

    /// Emits messages that follow from local state once sending is allowed:
    /// window adjustments, exit status and channel close.
    fn pump(&mut self) -> Result<(), Error> {
        if self.closed || self.tx_paused() || !self.chan.open {
            return Ok(());
        }
        let peer = self.chan.peer;
        if !self.chan.eof_in && !self.chan.close_in && !self.chan.close_out {
            let free = u32::try_from(self.ring.free()).unwrap_or(u32::MAX);
            let grant = free.saturating_sub(self.chan.recv_window);
            let half = u32::try_from(self.ring.capacity() / 2).unwrap_or(u32::MAX);
            if grant > 0 && grant >= half {
                self.send(msg::CHANNEL_WINDOW_ADJUST, |w| {
                    w.put_u32(peer)?;
                    w.put_u32(grant)
                })?;
                self.chan.recv_window = self.chan.recv_window.saturating_add(grant);
            }
        }
        if !self.chan.close_out {
            if let Some(code) = self.chan.exit.take() {
                self.send(msg::CHANNEL_REQUEST, |w| {
                    w.put_u32(peer)?;
                    w.put_string(b"exit-status")?;
                    w.put_bool(false)?;
                    w.put_u32(code)
                })?;
                self.send(msg::CHANNEL_EOF, |w| w.put_u32(peer))?;
                self.chan.eof_out = true;
            }
            if self.chan.eof_out || self.chan.close_in {
                self.send(msg::CHANNEL_CLOSE, |w| w.put_u32(peer))?;
                self.chan.close_out = true;
            }
        }
        if self.chan.close_in && self.chan.close_out {
            self.chan.open = false;
        }
        Ok(())
    }
}

/// Replies generated while our KEXINIT is outstanding, sent after NEWKEYS.
struct Defer<'a> {
    buf: &'a mut [u8],
    len: usize,
    count: usize,
}

impl Defer<'_> {
    fn push(&mut self, ty: u8, body: impl FnOnce(&mut Buf<'_>) -> Res) -> Result<(), Error> {
        const FULL: Error = Error::Protocol("too many messages during key exchange");
        if self.count >= DEFER_MAX {
            return Err(FULL);
        }
        // Records are a one-byte length followed by the payload.
        let start = self.len.saturating_add(1);
        let end = start
            .saturating_add(usize::from(u8::MAX))
            .min(self.buf.len());
        let mut w = Buf::new(self.buf.get_mut(start..end).ok_or(FULL)?);
        w.put_u8(ty).and_then(|()| body(&mut w)).map_err(|_| FULL)?;
        let n = w.len();
        *self.buf.get_mut(self.len).ok_or(FULL)? = u8::try_from(n).map_err(|_| FULL)?;
        self.len = start.saturating_add(n);
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    fn flush(&mut self, tx: &mut TxBuf<'_>, keys: &mut Keys) -> Result<(), Error> {
        let mut pos = 0;
        while pos < self.len {
            let n = usize::from(self.buf.get(pos).copied().unwrap_or_default());
            let start = pos.saturating_add(1);
            let end = start.saturating_add(n);
            let payload = self
                .buf
                .get(start..end)
                .ok_or(Error::Protocol("deferred message"))?;
            tx.packet(keys, n, |w| w.put_raw(payload))?;
            pos = end;
        }
        self.len = 0;
        self.count = 0;
        Ok(())
    }
}

/// Fixed-capacity ring buffer for client input.
struct Ring<'a> {
    buf: &'a mut [u8],
    head: usize,
    len: usize,
}

impl Ring<'_> {
    fn capacity(&self) -> usize {
        self.buf.len()
    }

    fn free(&self) -> usize {
        self.buf.len().saturating_sub(self.len)
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    /// The readable bytes up to the end of the buffer.
    fn front(&self) -> &[u8] {
        let end = self.head.saturating_add(self.len).min(self.buf.len());
        self.buf.get(self.head..end).unwrap_or_default()
    }

    fn consume(&mut self, n: usize) {
        let n = n.min(self.front().len());
        self.len = self.len.saturating_sub(n);
        self.head = self.head.saturating_add(n);
        if self.len == 0 || self.head >= self.buf.len() {
            self.head = if self.len == 0 {
                0
            } else {
                self.head.saturating_sub(self.buf.len())
            };
        }
    }

    /// Appends all of `data`, or nothing if it does not fit.
    fn push(&mut self, mut data: &[u8]) -> bool {
        if data.len() > self.free() {
            return false;
        }
        let cap = self.buf.len();
        while !data.is_empty() {
            let mut tail = self.head.saturating_add(self.len);
            if tail >= cap {
                tail = tail.saturating_sub(cap);
            }
            let limit = if tail < self.head { self.head } else { cap };
            let n = data.len().min(limit.saturating_sub(tail));
            let (now, later) = data.split_at(n);
            match self.buf.get_mut(tail..tail.saturating_add(n)) {
                Some(dst) if n > 0 => dst.copy_from_slice(now),
                _ => return false,
            }
            self.len = self.len.saturating_add(n);
            data = later;
        }
        true
    }
}
