//! A small SSH client that drives the server in memory. It reuses the
//! transport and key exchange code with the client role and checks the
//! server's behavior along the way (for example that nothing but KEX
//! messages arrive while the server's key exchange is in flight).
//! Its steady-state paths do not allocate, so allocation tests can measure
//! both sides at once.

use crate::Error;
use crate::cipher::Aead;
use crate::kex::{self, Ephemeral, Role};
use crate::keys::{HostKey, PublicKey};
use crate::sha256::Sha256;
use crate::transport::{Keys, RxBuf, TxBuf};
use crate::wire::{Buf, Hash, Msg, Put, Res, msg};

pub(crate) const VERSION: &[u8] = b"SSH-2.0-tinyssh-test";
/// Receive window the client grants the server.
pub(crate) const WINDOW: u32 = 256 * 1024;
const CHANNEL: u32 = 7;

/// Deterministic stream content: byte `i` is `i % 251`.
static PATTERN: [u8; 251 + 32 * 1024] = {
    let mut p = [0u8; 251 + 32 * 1024];
    let mut i = 0;
    while i < p.len() {
        p[i] = (i % 251) as u8;
        i += 1;
    }
    p
};

/// `len` bytes of the stream starting at `offset`.
pub(crate) fn pattern(offset: u64, len: usize) -> &'static [u8] {
    let start = (offset % 251) as usize;
    &PATTERN[start..start + len]
}

/// How the client's KEXINIT deviates from a normal one (negative tests).
#[derive(Clone, Copy)]
pub(crate) struct KexStyle {
    pub(crate) kex: &'static [u8],
    /// Set `first_kex_packet_follows` and send a (wrong) guessed packet.
    pub(crate) guess: bool,
}

pub(crate) struct Client<'a> {
    pub(crate) rx: RxBuf<'a>,
    pub(crate) rx_keys: Keys,
    pub(crate) tx: TxBuf<'a>,
    pub(crate) tx_keys: Keys,
    key: HostKey,
    user: &'static str,
    server_version: [u8; 255],
    server_version_len: usize,
    version_seen: bool,
    pub(crate) style: Option<KexStyle>,
    kexinit: [u8; 512],
    kexinit_len: usize,
    /// Our KEXINIT is out and our NEWKEYS is not: only KEX messages allowed.
    kex_sent: bool,
    hash: Option<Sha256>,
    ephemeral: Option<(Ephemeral, [u8; 32])>,
    next_rx: Option<Aead>,
    initial: bool,
    strict: bool,
    pub(crate) session_id: Option<[u8; 32]>,
    pub(crate) host_key: Option<PublicKey>,
    pub(crate) exchanges: u32,
    server_in_kex: bool,
    /// Non-KEX messages received during the server's key exchange.
    pub(crate) violations: u32,
    pub(crate) service_accepted: bool,
    pub(crate) authenticated: bool,
    pub(crate) auth_failures: u32,
    pub(crate) pk_ok: u32,
    pub(crate) channel: Option<u32>,
    pub(crate) send_window: u32,
    max_packet: u32,
    window: u32,
    unacked: u32,
    close_pending: bool,
    close_sent: bool,
    pub(crate) sent: u64,
    pub(crate) received: u64,
    pub(crate) stderr: u64,
    pub(crate) mismatches: u64,
    /// Largest data packet the client accepts (sent in CHANNEL_OPEN).
    pub(crate) accept_packet: u32,
    /// Initial window granted in CHANNEL_OPEN.
    pub(crate) open_window: u32,
    /// Data packets larger than `accept_packet`.
    pub(crate) oversized: u64,
    pub(crate) exit_status: Option<u32>,
    pub(crate) eof: bool,
    pub(crate) closed: bool,
    pub(crate) successes: u32,
    pub(crate) failures: u32,
    pub(crate) request_failures: u32,
    pub(crate) open_failures: u32,
    pub(crate) unimplemented: u32,
    pub(crate) disconnect: Option<u32>,
}

impl<'a> Client<'a> {
    /// A client that has queued nothing yet.
    pub(crate) fn idle(
        rx: &'a mut [u8],
        tx: &'a mut [u8],
        key: HostKey,
        user: &'static str,
    ) -> Self {
        Self {
            rx: RxBuf::new(rx),
            rx_keys: Keys::new(),
            tx: TxBuf::new(tx),
            tx_keys: Keys::new(),
            key,
            user,
            server_version: [0; 255],
            server_version_len: 0,
            version_seen: false,
            style: None,
            kexinit: [0; 512],
            kexinit_len: 0,
            kex_sent: false,
            hash: None,
            ephemeral: None,
            next_rx: None,
            initial: true,
            strict: false,
            session_id: None,
            host_key: None,
            exchanges: 0,
            server_in_kex: false,
            violations: 0,
            service_accepted: false,
            authenticated: false,
            auth_failures: 0,
            pk_ok: 0,
            channel: None,
            send_window: 0,
            max_packet: 0,
            window: 0,
            unacked: 0,
            close_pending: false,
            close_sent: false,
            sent: 0,
            received: 0,
            stderr: 0,
            mismatches: 0,
            accept_packet: 32 * 1024,
            open_window: WINDOW,
            oversized: 0,
            exit_status: None,
            eof: false,
            closed: false,
            successes: 0,
            failures: 0,
            request_failures: 0,
            open_failures: 0,
            unimplemented: 0,
            disconnect: None,
        }
    }

    /// Sends the identification line and KEXINIT.
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        self.tx.raw(VERSION)?;
        self.tx.raw(b"\r\n")?;
        self.send_kexinit()
    }

    /// Sends an arbitrary payload.
    pub(crate) fn packet(&mut self, body: impl FnOnce(&mut Buf<'_>) -> Res) -> Result<(), Error> {
        self.tx.packet(&mut self.tx_keys, 1024, body)
    }

    pub(crate) fn send_kexinit(&mut self) -> Result<(), Error> {
        let mut cookie = [0u8; 16];
        crate::rng::fill(&mut cookie)?;
        let initial = self.initial;
        let style = self.style;
        let mut w = Buf::new(&mut self.kexinit);
        let res: Res = match style {
            None => kex::write_kexinit(&mut w, &cookie, Role::Client, initial),
            Some(style) => (|| {
                w.put_u8(msg::KEXINIT)?;
                w.put_raw(&cookie)?;
                w.put_string(style.kex)?;
                w.put_string(kex::HOST_KEY_ALG)?;
                w.put_string(kex::CIPHER)?;
                w.put_string(kex::CIPHER)?;
                for list in [&b""[..], b"", b"none", b"none", b"", b""] {
                    w.put_string(list)?;
                }
                w.put_bool(style.guess)?;
                w.put_u32(0)
            })(),
        };
        res.map_err(|_| Error::Protocol("client kexinit"))?;
        self.kexinit_len = w.len();
        let payload = &self.kexinit[..self.kexinit_len];
        self.tx
            .packet(&mut self.tx_keys, 1024, |w| w.put_raw(payload))?;
        self.kex_sent = true;
        if style.is_some_and(|s| s.guess) {
            // A guessed key exchange packet the server must ignore.
            self.tx.packet(&mut self.tx_keys, 64, |w| {
                w.put_u8(msg::KEX_ECDH_INIT)?;
                w.put_string(&[0x55; 32])
            })?;
        }
        Ok(())
    }

    /// Starts a client-initiated key re-exchange.
    pub(crate) fn rekey(&mut self) -> Result<(), Error> {
        if !self.kex_sent && !self.initial {
            self.send_kexinit()?;
        }
        Ok(())
    }

    /// Copies server output into the receive buffer; returns bytes taken.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> usize {
        let space = self.rx.space();
        let n = space.len().min(bytes.len());
        space[..n].copy_from_slice(&bytes[..n]);
        self.rx.filled(n);
        n
    }

    /// Handles every complete message received so far.
    pub(crate) fn process(&mut self) -> Result<(), Error> {
        if !self.version_seen {
            let Some(line) = self.rx.line()? else {
                return Ok(());
            };
            let line = self.rx.get(line);
            self.server_version[..line.len()].copy_from_slice(line);
            self.server_version_len = line.len();
            self.version_seen = true;
        }
        while let Some(range) = self.rx.packet(&mut self.rx_keys)? {
            // Copy the payload out of the receive buffer (no allocation).
            let len = range.len();
            let mut payload = [0u8; 40 * 1024];
            payload[..len].copy_from_slice(self.rx.get(range));
            self.handle(&payload[..len])?;
        }
        self.flush_deferred()
    }

    /// Sends what had to wait for our own key exchange to finish.
    pub(crate) fn flush_deferred(&mut self) -> Result<(), Error> {
        if self.kex_sent {
            return Ok(());
        }
        if let Some(channel) = self.channel {
            if self.unacked >= WINDOW / 2 && !self.close_sent {
                let n = self.unacked;
                self.packet(|w| {
                    w.put_u8(msg::CHANNEL_WINDOW_ADJUST)?;
                    w.put_u32(channel)?;
                    w.put_u32(n)
                })?;
                self.window += n;
                self.unacked = 0;
            }
            if self.close_pending && !self.close_sent {
                self.close_pending = false;
                self.close()?;
            }
        }
        Ok(())
    }

    fn handle(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut m = Msg::new(payload);
        let ty = m.u8()?;
        if self.server_in_kex && !matches!(ty, 1..=4 | 20..=49) {
            self.violations += 1;
        }
        match ty {
            msg::KEXINIT => self.on_kexinit(payload)?,
            msg::KEX_ECDH_REPLY => self.on_reply(m)?,
            msg::NEWKEYS => {
                let next = self
                    .next_rx
                    .take()
                    .ok_or(Error::Protocol("early NEWKEYS"))?;
                self.rx_keys.install(next, self.strict);
                self.server_in_kex = false;
                self.initial = false;
                self.exchanges += 1;
            }
            msg::SERVICE_ACCEPT => self.service_accepted = true,
            msg::USERAUTH_SUCCESS => self.authenticated = true,
            msg::USERAUTH_FAILURE => self.auth_failures += 1,
            msg::USERAUTH_PK_OK => self.pk_ok += 1,
            msg::CHANNEL_OPEN_CONFIRMATION => {
                m.u32()?;
                self.channel = Some(m.u32()?);
                self.send_window = m.u32()?;
                self.max_packet = m.u32()?;
            }
            msg::CHANNEL_OPEN_FAILURE => self.open_failures += 1,
            msg::CHANNEL_WINDOW_ADJUST => {
                m.u32()?;
                self.send_window += m.u32()?;
            }
            msg::CHANNEL_DATA => {
                m.u32()?;
                let data = m.string()?;
                self.consume_window(data.len())?;
                if data.len() > self.accept_packet as usize {
                    self.oversized += 1;
                }
                if data != pattern(self.received, data.len()) {
                    self.mismatches += 1;
                }
                self.received += data.len() as u64;
            }
            msg::CHANNEL_EXTENDED_DATA => {
                m.u32()?;
                m.u32()?;
                let data = m.string()?;
                self.consume_window(data.len())?;
                self.stderr += data.len() as u64;
            }
            msg::CHANNEL_EOF => self.eof = true,
            msg::CHANNEL_CLOSE => {
                self.closed = true;
                if !self.close_sent {
                    self.close_pending = true;
                }
            }
            msg::CHANNEL_REQUEST => {
                m.u32()?;
                if m.string()? == b"exit-status" {
                    m.bool()?;
                    self.exit_status = Some(m.u32()?);
                }
            }
            msg::CHANNEL_SUCCESS => self.successes += 1,
            msg::CHANNEL_FAILURE => self.failures += 1,
            msg::REQUEST_FAILURE => self.request_failures += 1,
            msg::UNIMPLEMENTED => self.unimplemented += 1,
            msg::DISCONNECT => {
                self.disconnect = Some(m.u32()?);
                return Err(Error::Disconnected);
            }
            _ => {}
        }
        Ok(())
    }

    fn consume_window(&mut self, len: usize) -> Result<(), Error> {
        let len = u32::try_from(len).map_err(|_| Error::Protocol("huge data"))?;
        if len > self.window {
            return Err(Error::Protocol("server exceeded the client's window"));
        }
        self.window -= len;
        self.unacked += len;
        Ok(())
    }

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.server_in_kex = true;
        if !self.kex_sent {
            self.send_kexinit()?;
        }
        let peer = kex::negotiate(payload, Role::Client, self.initial)?;
        if self.initial {
            self.strict = peer.strict;
        }
        let mut hash = Sha256::new();
        let res: Res = (|| {
            let mut w = Hash(&mut hash);
            w.put_string(VERSION)?;
            w.put_string(&self.server_version[..self.server_version_len])?;
            w.put_string(&self.kexinit[..self.kexinit_len])?;
            w.put_string(payload)
        })();
        res.map_err(|_| Error::Protocol("hash"))?;
        self.hash = Some(hash);
        let (ephemeral, q_c) = Ephemeral::generate()?;
        self.tx.packet(&mut self.tx_keys, 64, |w| {
            w.put_u8(msg::KEX_ECDH_INIT)?;
            w.put_string(&q_c)
        })?;
        self.ephemeral = Some((ephemeral, q_c));
        Ok(())
    }

    fn on_reply(&mut self, mut m: Msg<'_>) -> Result<(), Error> {
        let host_blob = m.string()?;
        let q_s = m.fixed_string::<32>()?;
        let signature = m.string()?;
        m.end()?;
        let host = PublicKey::from_blob(host_blob).ok_or(Error::Protocol("bad host key"))?;
        if self.host_key.is_some_and(|known| known != host) {
            return Err(Error::Protocol("host key changed"));
        }
        let (ephemeral, q_c) = self
            .ephemeral
            .take()
            .ok_or(Error::Protocol("early reply"))?;
        let k = ephemeral.agree(&q_s)?;
        let mut hash = self.hash.take().ok_or(Error::Protocol("early reply"))?;
        Hash(&mut hash)
            .put_string(host_blob)
            .map_err(|_| Error::Protocol("hash"))?;
        let h = kex::finish_hash(hash, &q_c, &q_s, &k)?;
        if !host.verify(&[&h], signature) {
            return Err(Error::Protocol("bad host key signature"));
        }
        self.host_key = Some(host);
        let session_id = *self.session_id.get_or_insert(h);
        let (client_to_server, server_to_client) = kex::derive_keys(&k, &h, &session_id)?;
        self.tx
            .packet(&mut self.tx_keys, 8, |w| w.put_u8(msg::NEWKEYS))?;
        self.tx_keys.install(client_to_server, self.strict);
        self.next_rx = Some(server_to_client);
        self.kex_sent = false;
        Ok(())
    }

    pub(crate) fn service_request(&mut self) -> Result<(), Error> {
        self.packet(|w| {
            w.put_u8(msg::SERVICE_REQUEST)?;
            w.put_string(b"ssh-userauth")
        })
    }

    /// `publickey` authentication; `signed: false` sends the query form.
    pub(crate) fn auth(&mut self, signed: bool) -> Result<(), Error> {
        let session_id = self.session_id.ok_or(Error::Protocol("no session"))?;
        let blob = self.key.public_key().blob();
        let mut request = [0u8; 512];
        let mut w = Buf::new(&mut request);
        let res: Res = (|| {
            w.put_u8(msg::USERAUTH_REQUEST)?;
            w.put_string(self.user.as_bytes())?;
            w.put_string(b"ssh-connection")?;
            w.put_string(b"publickey")?;
            w.put_bool(signed)?;
            w.put_string(kex::HOST_KEY_ALG)?;
            w.put_string(&blob)
        })();
        res.map_err(|_| Error::Protocol("request"))?;
        let len = w.len();
        let request = &request[..len];
        if !signed {
            return self.packet(|w| w.put_raw(request));
        }
        let mut data = [0u8; 600];
        let mut w = Buf::new(&mut data);
        w.put_string(&session_id)
            .and_then(|()| w.put_raw(request))
            .map_err(|_| Error::Protocol("sign"))?;
        let n = w.len();
        let sig_blob = self.key.sign(&data[..n]);
        self.packet(|w| {
            w.put_raw(request)?;
            w.put_string(&sig_blob)
        })
    }

    pub(crate) fn open_session(&mut self) -> Result<(), Error> {
        let window = self.open_window;
        self.window = window;
        self.unacked = 0;
        self.close_sent = false;
        self.closed = false;
        self.eof = false;
        self.exit_status = None;
        let accept_packet = self.accept_packet;
        self.packet(|w| {
            w.put_u8(msg::CHANNEL_OPEN)?;
            w.put_string(b"session")?;
            w.put_u32(CHANNEL)?;
            w.put_u32(window)?;
            w.put_u32(accept_packet)
        })
    }

    /// Grants the server `n` more bytes of window.
    #[cfg(target_os = "linux")]
    pub(crate) fn adjust_window(&mut self, n: u32) -> Result<(), Error> {
        let channel = self.channel.ok_or(Error::Protocol("no channel"))?;
        self.packet(|w| {
            w.put_u8(msg::CHANNEL_WINDOW_ADJUST)?;
            w.put_u32(channel)?;
            w.put_u32(n)
        })?;
        self.window += n;
        Ok(())
    }

    /// A channel request on the open session.
    pub(crate) fn request(
        &mut self,
        kind: &[u8],
        want_reply: bool,
        extra: impl FnOnce(&mut Buf<'_>) -> Res,
    ) -> Result<(), Error> {
        let channel = self.channel.ok_or(Error::Protocol("no channel"))?;
        self.packet(|w| {
            w.put_u8(msg::CHANNEL_REQUEST)?;
            w.put_u32(channel)?;
            w.put_string(kind)?;
            w.put_bool(want_reply)?;
            extra(w)
        })
    }

    pub(crate) fn pty(&mut self, term: &[u8], cols: u32, rows: u32) -> Result<(), Error> {
        self.request(b"pty-req", true, |w| {
            w.put_string(term)?;
            for v in [cols, rows, 0, 0] {
                w.put_u32(v)?;
            }
            w.put_string(&[0])
        })
    }

    pub(crate) fn exec(&mut self, command: &[u8]) -> Result<(), Error> {
        self.request(b"exec", true, |w| w.put_string(command))
    }

    pub(crate) fn window_change(&mut self, cols: u32, rows: u32) -> Result<(), Error> {
        self.request(b"window-change", false, |w| {
            for v in [cols, rows, 0, 0] {
                w.put_u32(v)?;
            }
            Ok(())
        })
    }

    pub(crate) fn global_request(&mut self, want_reply: bool) -> Result<(), Error> {
        self.packet(|w| {
            w.put_u8(msg::GLOBAL_REQUEST)?;
            w.put_string(b"keepalive@openssh.com")?;
            w.put_bool(want_reply)
        })
    }

    /// Sends up to `max` bytes of the test pattern as channel data.
    pub(crate) fn send_data(&mut self, max: usize) -> Result<usize, Error> {
        let Some(channel) = self.channel else {
            return Ok(0);
        };
        if self.kex_sent || self.close_sent {
            return Ok(0);
        }
        let n = max
            .min(self.send_window as usize)
            .min(self.max_packet as usize)
            .min(32 * 1024);
        if n == 0 || self.tx.free() < n + 128 {
            return Ok(0);
        }
        let data = pattern(self.sent, n);
        self.tx.packet(&mut self.tx_keys, n + 16, |w| {
            w.put_u8(msg::CHANNEL_DATA)?;
            w.put_u32(channel)?;
            w.put_string(data)
        })?;
        self.send_window -= n as u32;
        self.sent += n as u64;
        Ok(n)
    }

    /// Sends up to `max` bytes as extended (type 1) channel data.
    pub(crate) fn send_extended(&mut self, max: usize) -> Result<usize, Error> {
        let Some(channel) = self.channel else {
            return Ok(0);
        };
        let n = max
            .min(self.send_window as usize)
            .min(self.max_packet as usize);
        if self.kex_sent || self.close_sent || n == 0 || self.tx.free() < n + 128 {
            return Ok(0);
        }
        self.tx.packet(&mut self.tx_keys, n + 16, |w| {
            w.put_u8(msg::CHANNEL_EXTENDED_DATA)?;
            w.put_u32(channel)?;
            w.put_u32(1)?;
            w.put_string(&[b'e'; 32 * 1024][..n])
        })?;
        self.send_window -= n as u32;
        Ok(n)
    }

    pub(crate) fn send_eof(&mut self) -> Result<(), Error> {
        let channel = self.channel.ok_or(Error::Protocol("no channel"))?;
        self.packet(|w| {
            w.put_u8(msg::CHANNEL_EOF)?;
            w.put_u32(channel)
        })
    }

    pub(crate) fn close(&mut self) -> Result<(), Error> {
        let channel = self.channel.ok_or(Error::Protocol("no channel"))?;
        self.close_sent = true;
        self.packet(|w| {
            w.put_u8(msg::CHANNEL_CLOSE)?;
            w.put_u32(channel)
        })
    }
}
